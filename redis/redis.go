package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/go-redis/redis/v8"
)

const (
	CacheChannelName string = "blocky_cache_sync"
	CacheStorePrefix string = "cache:"
)

// Client for redis communication
type Client struct {
	config  *config.RedisConfig
	context *context.Context
	client  *redis.Client
	Channel chan *model.ResponseCache
}

// New creates a new redis client
func New(cfg *config.RedisConfig) (*Client, error) {
	// disable redis if no address is provided
	if cfg == nil || len(cfg.Address) == 0 {
		return nil, nil
	}

	ctx := context.Background()

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Address,
		Password: cfg.Password,
		DB:       cfg.Database,
	})

	var err error

	attempt := 1
	for attempt <= cfg.ConnectionAttempts {
		err = rdb.Ping(ctx).Err()
		if err == nil {
			// construct client
			res := &Client{
				config:  cfg,
				context: &ctx,
				client:  rdb,
				Channel: make(chan *model.ResponseCache),
			}

			defer func() {
				close(res.Channel)
			}()

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
	msg := &model.ResponseCache{
		Key:      key,
		Response: response,
	}

	go func() {
		c.client.Publish(*c.context, CacheChannelName, msg)
		c.client.Set(*c.context, prefixKey(key), response, time.Duration(0))
	}()
}

// GetRedisCache reads the redis cache and publish it to the channel
func (c *Client) GetRedisCache() {
	// start routine to get the cache
	go func(ch chan<- *model.ResponseCache) {
		iter := c.client.Scan(*c.context, 0, fmt.Sprintf("%s*", CacheStorePrefix), 0).Iterator()
		for iter.Next(*c.context) {
			prefkey := iter.Val()
			response, err := c.getResponse(prefkey)

			if err == nil {
				msg := &model.ResponseCache{
					Key:      deprefixKey(prefkey),
					Response: response,
				}
				ch <- msg
			}
		}
	}(c.Channel)
}

// startSubscriptionListener starts a new goroutine for subscription and translation
func (c *Client) startSubscriptionListener() error {
	ps := c.client.Subscribe(*c.context, CacheChannelName)
	defer ps.Close()

	_, err := ps.Receive(*c.context)
	if err == nil {
		pschan := ps.Channel()

		go func(ch chan<- *model.ResponseCache) {
			for msg := range pschan {
				m := &model.ResponseCache{}

				mErr := m.UnmarshalBinary([]byte(msg.Payload))
				if mErr == nil {
					ch <- m
				}
			}
		}(c.Channel)
	}

	return err
}

// getResponse returns model.Response for a key
func (c *Client) getResponse(key string) (*model.Response, error) {
	resp, err := c.client.Get(*c.context, key).Result()
	if err == nil {
		res := &model.Response{}

		err = json.Unmarshal([]byte(resp), res)
		if err == nil {
			return res, nil
		}
	}

	return nil, err
}

// prefixKey prefixes a key
func prefixKey(key string) string {
	return fmt.Sprintf("%s%s", CacheStorePrefix, key)
}

// deprefixKey get the key from a prefixed one
func deprefixKey(key string) string {
	return strings.TrimPrefix(key, CacheStorePrefix)
}
