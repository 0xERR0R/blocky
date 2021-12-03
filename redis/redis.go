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

type Client struct {
	config  *config.RedisConfig
	context *context.Context
	client  *redis.Client
	Channel chan *model.ResponseCache
}

// New creates a new redis client
func New(cfg *config.RedisConfig) (*Client, error) {
	if len(cfg.Address) == 0 {
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

			res := &Client{
				config:  cfg,
				context: &ctx,
				client:  rdb,
				Channel: make(chan *model.ResponseCache),
			}

			return res, nil
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

func (c *Client) GetRedisCache() {
	go func() {
		iter := c.client.Scan(*c.context, 0, fmt.Sprintf("%s*", CacheStorePrefix), 0).Iterator()
		for iter.Next(*c.context) {
			prefkey := iter.Val()
			response, err := c.getResponse(prefkey)

			if err == nil {
				msg := &model.ResponseCache{
					Key:      deprefixKey(prefkey),
					Response: response,
				}
				c.Channel <- msg
			}
		}
	}()
}

func (c *Client) getResponse(key string) (*model.Response, error) {
	resp := c.client.Get(*c.context, key)
	err := resp.Err()
	if err == nil {
		var res model.Response
		json.Unmarshal([]byte(resp.String()), res)
		return &res, nil
	}
	return nil, err
}

func prefixKey(key string) string {
	return fmt.Sprintf("%s%s", CacheStorePrefix, key)
}

func deprefixKey(key string) string {
	return strings.TrimPrefix(key, CacheStorePrefix)
}
