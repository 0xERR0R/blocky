package redis

import (
	"context"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/go-redis/redis/v8"
)

const (
	CacheChannelName string = "blocky_cache_sync"
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

	err := rdb.Ping(ctx).Err()
	if err == nil {
		res := &Client{
			config:  cfg,
			context: &ctx,
			client:  rdb,
		}

		return res, nil
	}

	return nil, err
}

// PublishCache publish cache to redis async
func (c *Client) PublishCache(key string, data *model.Response) {
	msg := &CacheMessage{
		Key:      key,
		Response: data,
	}

	go func() {
		c.client.Publish(*c.context, CacheChannelName, msg)
	}()
}
