package redis

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

const (
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

// Client for redis communication
type Client struct {
	config         *config.Redis
	client         *redis.Client
	l              *logrus.Entry
	id             []byte
	sendBuffer     chan *bufferMessage
	CacheChannel   chan *CacheMessage
	EnabledChannel chan *EnabledMessage
}

// New creates a new redis client
func New(ctx context.Context, cfg *config.Redis) (*Client, error) {
	// disable redis if no address is provided
	if cfg == nil || len(cfg.Address) == 0 {
		return nil, nil //nolint:nilnil
	}

	var baseClient *redis.Client
	if len(cfg.SentinelAddresses) > 0 {
		baseClient = redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName:       cfg.Address,
			SentinelUsername: cfg.Username,
			SentinelPassword: cfg.SentinelPassword,
			SentinelAddrs:    cfg.SentinelAddresses,
			Username:         cfg.Username,
			Password:         cfg.Password,
			DB:               cfg.Database,
			MaxRetries:       cfg.ConnectionAttempts,
			MaxRetryBackoff:  cfg.ConnectionCooldown.ToDuration(),
		})
	} else {
		baseClient = redis.NewClient(&redis.Options{
			Addr:            cfg.Address,
			Username:        cfg.Username,
			Password:        cfg.Password,
			DB:              cfg.Database,
			MaxRetries:      cfg.ConnectionAttempts,
			MaxRetryBackoff: cfg.ConnectionCooldown.ToDuration(),
		})
	}

	rdb := baseClient.WithContext(ctx)

	_, err := rdb.Ping(ctx).Result()
	if err == nil {
		var id []byte

		id, err = uuid.New().MarshalBinary()
		if err == nil {
			// construct client
			res := &Client{
				config:         cfg,
				client:         rdb,
				l:              log.PrefixedLog("redis"),
				id:             id,
				sendBuffer:     make(chan *bufferMessage, chanCap),
				CacheChannel:   make(chan *CacheMessage, chanCap),
				EnabledChannel: make(chan *EnabledMessage, chanCap),
			}

			// start channel handling go routine
			err = res.startup(ctx)

			return res, err
		}
	}

	return nil, err
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
			c.client.Publish(ctx, SyncChannelName, binMsg)
		}
	}
}

// GetRedisCache reads the redis cache and publish it to the channel
func (c *Client) GetRedisCache(ctx context.Context) {
	c.l.Debug("GetRedisCache")

	go func() {
		iter := c.client.Scan(ctx, 0, prefixKey("*"), 0).Iterator()
		if err := iter.Err(); err != nil {
			c.l.Error("GetRedisCache ", err)

			return
		}

		for iter.Next(ctx) {
			response, err := c.getResponse(ctx, iter.Val())
			if err == nil {
				if response != nil {
					if !util.CtxSend(ctx, c.CacheChannel, response) {
						return
					}
				}
			} else {
				c.l.Error("GetRedisCache ", err)
			}
		}
	}()
}

// startup starts a new goroutine for subscription and translation
func (c *Client) startup(ctx context.Context) error {
	ps := c.client.Subscribe(ctx, SyncChannelName)

	_, err := ps.Receive(ctx)
	if err == nil {
		go func() {
			for {
				select {
				// received message from subscription
				case msg := <-ps.Channel():
					c.l.Debug("Received message: ", msg)

					if msg != nil && len(msg.Payload) > 0 {
						// message is not empty
						c.processReceivedMessage(ctx, msg)
					}
					// publish message from buffer
				case s := <-c.sendBuffer:
					c.publishMessageFromBuffer(ctx, s)
				// context is done
				case <-ctx.Done():
					c.client.Close()

					return
				}
			}
		}()
	}

	return err
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
			c.client.Publish(ctx, SyncChannelName, binMsg)
		}

		c.client.Set(ctx,
			prefixKey(s.Key),
			binRes,
			c.getTTL(origRes))
	}
}

func (c *Client) processReceivedMessage(ctx context.Context, msg *redis.Message) {
	var rm redisMessage

	if err := json.Unmarshal([]byte(msg.Payload), &rm); err != nil {
		c.l.Error("Processing error: ", err)

		return
	}

	// message was sent from a different blocky instance
	if !bytes.Equal(rm.Client, c.id) {
		switch rm.Type {
		case messageTypeCache:
			var cm *CacheMessage

			cm, err := convertMessage(&rm, 0)
			if err != nil {
				c.l.Error("Processing CacheMessage error: ", err)

				return
			}

			util.CtxSend(ctx, c.CacheChannel, cm)
		case messageTypeEnable:
			var msg EnabledMessage

			if err := json.Unmarshal(rm.Message, &msg); err != nil {
				c.l.Error("Processing EnabledMessage error: ", err)

				return
			}

			util.CtxSend(ctx, c.EnabledChannel, &msg)
		default:
			c.l.Warn("Unknown message type: ", rm.Type)
		}
	}
}

// getResponse returns model.Response for a key
func (c *Client) getResponse(ctx context.Context, key string) (*CacheMessage, error) {
	resp, err := c.client.Get(ctx, key).Result()
	if err == nil {
		var ttl time.Duration
		ttl, err = c.client.TTL(ctx, key).Result()

		if err == nil {
			var result *CacheMessage

			result, err = convertMessage(&redisMessage{
				Key:     cleanKey(key),
				Message: []byte(resp),
			}, ttl)
			if err != nil {
				return nil, fmt.Errorf("conversion error: %w", err)
			}

			return result, nil
		}
	}

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
func (c *Client) getTTL(dns *dns.Msg) time.Duration {
	ttl := uint32(math.MaxInt32)
	for _, a := range dns.Answer {
		ttl = min(ttl, a.Header().Ttl)
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
