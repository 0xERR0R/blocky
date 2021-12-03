package redis

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/go-redis/redis/v8"
)

const (
	CacheChannelName   string = "blocky_cache_sync"
	CacheMessagePrefix string = "cache:"
)

type Client struct {
	config  *config.RedisConfig
	context *context.Context
	client  *redis.Client
}

func New(cfg *config.RedisConfig) (*Client, error) {
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

func prefixKey(key string) string {
	return fmt.Sprintf("%s%s", CacheMessagePrefix, key)
}

func deprefixKey(key string) string {
	return strings.TrimPrefix(key, CacheMessagePrefix)
}
