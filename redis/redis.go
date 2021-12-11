package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

const (
	CacheChannelName string = "blocky_cache_sync"
	CacheStorePrefix string = "blocky:cache:"
)

type CacheMessage struct {
	Key      string
	Response *model.Response
}

// Client for redis communication
type Client struct {
	config  *config.RedisConfig
	client  *redis.Client
	l       *logrus.Entry
	ctx     context.Context
	Channel chan *CacheMessage
}

// New creates a new redis client
func New(cfg *config.RedisConfig) (*Client, error) {
	// disable redis if no address is provided
	if cfg == nil || len(cfg.Address) == 0 {
		return nil, nil
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Address,
		Password: cfg.Password,
		DB:       cfg.Database,
	})
	ctx := context.Background()

	var err error
	var msg string

	attempt := 1
	for attempt <= cfg.ConnectionAttempts {
		msg, err = rdb.Ping(ctx).Result()
		if err == nil && msg == "PONG" {
			// construct client
			res := &Client{
				config:  cfg,
				client:  rdb,
				l:       log.PrefixedLog("redis"),
				ctx:     ctx,
				Channel: make(chan *CacheMessage),
			}

			// start listener
			pserr := res.startSubscriptionListener()

			return res, pserr
		}

		time.Sleep(time.Duration(cfg.ConnectionCooldown))
		attempt++
	}

	return nil, err
}

// PublishCache publish cache to redis async
func (c *Client) PublishCache(key string, response *model.Response) {
	msg, errConv := response.ConvertToCache(key)
	if errConv == nil {
		binMsg, errMar := msg.MarshalBinary()
		if errMar == nil {
			go func() {
				c.client.Publish(c.ctx, CacheChannelName, binMsg)
				c.client.Set(c.ctx, prefixKey(key), binMsg, time.Duration(0))
			}()
		} else {
			c.l.Error("PublishCache marshal error ", errMar)
		}
	} else {
		c.l.Error("PublishCache convert error ", errConv)
	}
}

// GetRedisCache reads the redis cache and publish it to the channel
func (c *Client) GetRedisCache() {
	// start routine to get the cache
	go func() {
		iter := c.client.Scan(c.ctx, 0, fmt.Sprintf("%s*", CacheStorePrefix), 0).Iterator()
		for iter.Next(c.ctx) {
			response, err := c.getResponse(iter.Val())
			if err == nil {
				if response != nil {
					c.Channel <- response
				}
			} else {
				c.l.Error("GetRedisCache ", err)
			}
		}
	}()
}

// startSubscriptionListener starts a new goroutine for subscription and translation
func (c *Client) startSubscriptionListener() error {
	ps := c.client.Subscribe(c.ctx, CacheChannelName)

	_, err := ps.Receive(c.ctx)
	if err == nil {
		go func() {
			for msg := range ps.Channel() {
				c.l.Debug("Received message: ", msg)

				m, err := convertPayload(msg)
				if err == nil {
					if m != nil {
						c.Channel <- m
					}
				} else {
					c.l.Error("Conversion error: ", err)
				}
			}
		}()
	}

	return err
}

// getResponse returns model.Response for a key
func (c *Client) getResponse(key string) (*CacheMessage, error) {
	resp, err := c.client.Get(c.ctx, key).Result()
	if err == nil {
		var result *CacheMessage

		result, err = convertMessage(resp)
		if err == nil {
			return result, nil
		}

		c.l.Error("Conversion error: ", err)
	}

	return nil, err
}

// prefixKey prefixes a key
func prefixKey(key string) string {
	return fmt.Sprintf("%s%s", CacheStorePrefix, key)
}

func convertPayload(message *redis.Message) (*CacheMessage, error) {
	if message != nil {
		return convertMessage(message.Payload)
	}

	return nil, nil
}

func convertMessage(message string) (*CacheMessage, error) {
	var err error

	if len(message) > 0 {
		m := &model.ResponseCache{}

		err := m.UnmarshalString(message)
		if err == nil {
			var key string
			var response *model.Response

			key, response, err = m.ConvertFromCache()
			if err == nil {
				result := &CacheMessage{
					Key:      key,
					Response: response,
				}

				return result, nil
			}
		}
	}

	return nil, err
}
