package redis

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/avast/retry-go/v4"
	"github.com/google/uuid"
	"github.com/miekg/dns"
	"github.com/rueian/rueidis"
	"github.com/rueian/rueidis/rueidislock"
	"github.com/sirupsen/logrus"
)

const (
	blockyBaseKey     = "blocky"
	blockyLockerKey   = "locker"
	blockyTickerKey   = "ticker"
	blockyCacheKey    = "cache"
	SyncChannelName   = "blocky_sync"
	CacheStorePrefix  = "blocky:cache:"
	chanCap           = 1000
	cacheReason       = "EXTERNAL_CACHE"
	defaultCacheTime  = 1 * time.Second
	messageTypeCache  = 0
	messageTypeEnable = 1
)

// sendBuffer message
type bufferMessage struct {
	Key     string
	Message *dns.Msg
}

// redis pubsub message
type redisMessage struct {
	Key     string `json:"k,omitempty"`
	Type    int    `json:"t"`
	Message []byte `json:"m"`
	Client  []byte `json:"c"`
}

// CacheChannel message
type CacheMessage struct {
	Key      string
	Response *model.Response
}

type EnabledMessage struct {
	State    bool          `json:"s"`
	Duration time.Duration `json:"d,omitempty"`
	Groups   []string      `json:"g,omitempty"`
}

// ClientKeys stores the primary redis keys
type ClientKeys struct {
	Base   *Key
	Locker *Key
	Ticker *Key
	Cache  *Key
}

// Client for redis communication
type Client struct {
	Keys           *ClientKeys
	config         *config.RedisConfig
	Client         rueidis.Client
	locker         rueidislock.Locker
	l              *logrus.Entry
	id             []byte
	LocalCacheTime TTL
	sendBuffer     chan *bufferMessage
	CacheChannel   chan *CacheMessage
	EnabledChannel chan *EnabledMessage
}

// New creates a new redis client
func New(ctx context.Context, cfg *config.RedisConfig) (*Client, error) {
	// disable redis if no address is provided
	if cfg == nil || !cfg.IsEnabled() {
		return nil, nil //nolint:nilnil
	}

	id, err := uuid.New().MarshalBinary()
	if err != nil {
		return nil, err
	}

	bk := newKey(cfg.Database, blockyBaseKey)
	lk := bk.NewSubkey(blockyLockerKey)

	l := log.PrefixedLog("redis")

	client, err := getRueidisClient(cfg)
	if err != nil {
		return nil, err
	}

	locker, err := getRueidisLocker(lk, cfg)
	if err != nil {
		defer client.Close()

		return nil, err
	}

	res := &Client{
		Keys: &ClientKeys{
			Base:   bk,
			Locker: lk,
			Ticker: bk.NewSubkey(blockyTickerKey),
			Cache:  bk.NewSubkey(blockyCacheKey),
		},
		config:         cfg,
		Client:         client,
		locker:         locker,
		l:              l,
		id:             id,
		LocalCacheTime: TTL(cfg.LocalCacheTime),
		sendBuffer:     make(chan *bufferMessage, chanCap),
		CacheChannel:   make(chan *CacheMessage, chanCap),
		EnabledChannel: make(chan *EnabledMessage, chanCap),
	}

	res.startup(ctx)

	return res, nil
}

// Close all channels and client
func (c *Client) Close() {
	defer c.Client.Close()
	defer c.locker.Close()
	defer close(c.sendBuffer)
	defer close(c.CacheChannel)
	defer close(c.EnabledChannel)
}

// GetTicker returns a named ticker
func (c *Client) GetTicker(name string, d time.Duration) (*Ticker, error) {
	return newTicker(TTL(d), name, c.Keys.Ticker, c.Client, c.locker)
}

func (c *Client) RunLocked(ctx context.Context, wait bool, name string, ex func(context.Context)) bool {
	var lctx context.Context
	var lcancel func()
	var lerr error

	if wait {
		lctx, lcancel, lerr = c.locker.WithContext(ctx, name)
	} else {
		lctx, lcancel, lerr = c.locker.TryWithContext(ctx, name)
	}

	if lerr != nil {
		c.l.Debug(lerr)

		return false
	}

	defer lcancel()

	ex(lctx)

	return true
}

// PublishCache publish cache to redis async
func (c *Client) PublishCache(key string, message *dns.Msg) {
	if len(key) > 0 && message != nil {
		c.sendBuffer <- &bufferMessage{
			Key:     key,
			Message: message,
		}
	}
}

func (c *Client) PublishEnabled(ctx context.Context, state *EnabledMessage) {
	binState, sErr := json.Marshal(state)
	if sErr == nil {
		binMsg, mErr := json.Marshal(redisMessage{
			Type:    messageTypeEnable,
			Message: binState,
			Client:  c.id,
		})

		if mErr == nil {
			c.Client.Do(ctx,
				c.Client.B().Publish().
					Channel(SyncChannelName).
					Message(rueidis.BinaryString(binMsg)).
					Build())
		}
	}
}

// GetRedisCache reads the redis cache and publishes it to the channel
func (c *Client) GetRedisCache(ctx context.Context) {
	c.l.Debug("GetRedisCache")

	go func() {
		var cursor uint64

		searchKey := prefixKey("*")

		for {
			sres, err := c.Client.Do(ctx, c.Client.B().Scan().Cursor(cursor).Match(searchKey).Count(1).Build()).AsScanEntry()
			if err != nil {
				c.l.Errorf("could not start a searching through Redis cache: %s", err)

				break
			}

			cursor = sres.Cursor

			for _, key := range sres.Elements {
				c.l.Debugf("GetRedisCache: %s", key)

				resp := c.Client.Do(ctx, c.Client.B().Get().Key(key).Build())

				if resp.Error() == nil {
					str, err := resp.ToString()
					if err == nil {
						response, err := c.getResponse(ctx, str)
						if err == nil {
							c.CacheChannel <- response
						}
					}
				}
			}

			if cursor == 0 { // no more keys
				break
			}
		}
	}()
}

// startup starts a new goroutine for subscription and translation
func (c *Client) startup(ctx context.Context) {
	go func() {
		dc, cancel := c.Client.Dedicate()
		defer cancel()

		wait := dc.SetPubSubHooks(rueidis.PubSubHooks{
			OnMessage: func(m rueidis.PubSubMessage) {
				if m.Channel == SyncChannelName {
					c.l.Debug("Received message: ", m)

					if len(m.Message) > 0 {
						// message is not empty
						c.processReceivedMessage(m.Message)
					}
				}
			},
		})

		dc.Do(ctx, dc.B().Subscribe().Channel(SyncChannelName).Build())

		for {
			select {
			case <-wait:
				return
			// publish message from buffer
			case s := <-c.sendBuffer:
				c.publishMessageFromBuffer(ctx, s)
			}
		}
	}()
}

func (c *Client) publishMessageFromBuffer(ctx context.Context, s *bufferMessage) {
	origRes := s.Message
	origRes.Compress = true
	binRes, pErr := origRes.Pack()

	if pErr == nil {
		binMsg, mErr := json.Marshal(redisMessage{
			Key:     s.Key,
			Type:    messageTypeCache,
			Message: binRes,
			Client:  c.id,
		})

		if mErr == nil {
			c.Client.Do(ctx,
				c.Client.B().Publish().
					Channel(SyncChannelName).
					Message(rueidis.BinaryString(binMsg)).
					Build())
		}

		c.Client.Do(ctx,
			c.Client.B().Setex().
				Key(prefixKey(s.Key)).
				Seconds(int64(c.getTTL(origRes).Seconds())).
				Value(rueidis.BinaryString(binRes)).
				Build())
	}
}

func (c *Client) processReceivedMessage(msgPayload string) {
	var rm redisMessage

	err := json.Unmarshal([]byte(msgPayload), &rm)
	if err == nil {
		// message was sent from a different blocky instance
		if !bytes.Equal(rm.Client, c.id) {
			switch rm.Type {
			case messageTypeCache:
				var cm *CacheMessage

				cm, err = convertMessage(&rm, 0)
				if err == nil {
					c.CacheChannel <- cm
				}
			case messageTypeEnable:
				err = c.processEnabledMessage(&rm)
			default:
				c.l.Warn("Unknown message type: ", rm.Type)
			}
		}
	}

	if err != nil {
		c.l.Error("Processing error: ", err)
	}
}

func (c *Client) processEnabledMessage(redisMsg *redisMessage) error {
	var msg EnabledMessage

	err := json.Unmarshal(redisMsg.Message, &msg)
	if err == nil {
		c.EnabledChannel <- &msg
	}

	return err
}

// getResponse returns model.Response for a key
func (c *Client) getResponse(ctx context.Context, key string) (*CacheMessage, error) {
	resp, err := c.Client.Do(ctx, c.Client.B().Get().Key(key).Build()).AsBytes()
	if err == nil {
		uittl, err := c.Client.Do(ctx,
			c.Client.B().Ttl().
				Key(key).
				Build()).AsUint64()
		ttl := time.Second * time.Duration(uittl)

		if err == nil {
			var result *CacheMessage

			result, err = convertMessage(&redisMessage{
				Key:     cleanKey(key),
				Message: resp,
			}, ttl)
			if err != nil {
				return nil, fmt.Errorf("conversion error: %w", err)
			}

			return result, nil
		}
	}

	c.l.Debugf("Error fetching %s: %v", key, err)

	return nil, err
}

// convertMessage converts redisMessage to CacheMessage
func convertMessage(message *redisMessage, ttl time.Duration) (*CacheMessage, error) {
	msg := dns.Msg{}

	err := msg.Unpack(message.Message)
	if err == nil {
		if ttl > 0 {
			for _, a := range msg.Answer {
				a.Header().Ttl = uint32(ttl.Seconds())
			}
		}

		res := &CacheMessage{
			Key: message.Key,
			Response: &model.Response{
				RType:  model.ResponseTypeCACHED,
				Reason: cacheReason,
				Res:    &msg,
			},
		}

		return res, nil
	}

	return nil, err
}

// getTTL of dns message or return defaultCacheTime if 0
func (c *Client) getTTL(msg *dns.Msg) time.Duration {
	ttl := uint32(0)
	for _, a := range msg.Answer {
		if a.Header().Ttl > ttl {
			ttl = a.Header().Ttl
		}
	}

	if ttl == 0 {
		return defaultCacheTime
	}

	return time.Duration(ttl) * time.Second
}

// prefixKey with CacheStorePrefix
func prefixKey(key string) string {
	return fmt.Sprintf("%s%s", CacheStorePrefix, key)
}

// cleanKey trims CacheStorePrefix prefix
func cleanKey(key string) string {
	return strings.TrimPrefix(key, CacheStorePrefix)
}

func getRueidisClientOption(cfg *config.RedisConfig) *rueidis.ClientOption {
	res := cfg.GetClientOptions()

	res.ClientName = fmt.Sprintf("blocky-%s", util.HostnameString())

	return res
}

func getRueidisClient(cfg *config.RedisConfig) (rueidis.Client, error) {
	roption := getRueidisClientOption(cfg)

	var client rueidis.Client

	err := retry.Do(
		func() error {
			var ierr error

			client, ierr = rueidis.NewClient(*roption)

			return ierr
		},
		retry.Attempts(cfg.ConnectionAttempts),
		retry.Delay(time.Duration(cfg.ConnectionCooldown)),
	)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func getRueidisLocker(k *Key, cfg *config.RedisConfig) (rueidislock.Locker, error) {
	loption := rueidislock.LockerOption{
		ClientOption: *getRueidisClientOption(cfg),
		KeyPrefix:    k.String(),
	}

	var locker rueidislock.Locker

	err := retry.Do(
		func() error {
			var ierr error

			locker, ierr = rueidislock.NewLocker(loption)

			return ierr
		},
		retry.Attempts(cfg.ConnectionAttempts),
		retry.Delay(time.Duration(cfg.ConnectionCooldown)),
	)
	if err != nil {
		return nil, err
	}

	return locker, nil
}
