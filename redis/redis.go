package redis

import (
	"context"

	"github.com/0xERR0R/blocky/config"
	"github.com/go-redis/redis/v8"
)

const (
	CacheChannelName string = "blocky_cache_sync"
)

type RedisClient struct {
	config  *config.RedisConfig
	context *context.Context
	client  *redis.Client
}

func New(cfg *config.RedisConfig) (*RedisClient, error) {
	ctx := context.Background()

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Address,
		Password: cfg.Password,
		DB:       cfg.Database,
	})

	err := rdb.Ping(ctx).Err()
	if err == nil {
		res := &RedisClient{
			config:  cfg,
			context: &ctx,
			client:  rdb,
		}
		return res, nil
	} else {
		return nil, err
	}
}
