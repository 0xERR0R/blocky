package redis

import (
	"context"
	"fmt"

	"github.com/0xERR0R/blocky/config"
	goredis "github.com/go-redis/redis/v8"
)

// New creates a new Redis connection. Returns nil if Redis is not configured.
func New(ctx context.Context, cfg *config.Redis) (*goredis.Client, error) {
	if cfg == nil || len(cfg.Address) == 0 {
		return nil, nil //nolint:nilnil
	}

	var client *goredis.Client
	if len(cfg.SentinelAddresses) > 0 {
		client = goredis.NewFailoverClient(&goredis.FailoverOptions{
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
		client = goredis.NewClient(&goredis.Options{
			Addr:            cfg.Address,
			Username:        cfg.Username,
			Password:        cfg.Password,
			DB:              cfg.Database,
			MaxRetries:      cfg.ConnectionAttempts,
			MaxRetryBackoff: cfg.ConnectionCooldown.ToDuration(),
		})
	}

	rdb := client.WithContext(ctx)

	if _, err := rdb.Ping(ctx).Result(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis at '%s': %w", cfg.Address, err)
	}

	return rdb, nil
}
