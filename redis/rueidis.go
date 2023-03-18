package redis

import (
	"fmt"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/util"
	"github.com/rueian/rueidis"
)

// New creates a new redis client
func NewRedisClient(cfg *config.RedisConfig) (rueidis.Client, error) {
	// disable redis if no address is provided
	if cfg == nil || len(cfg.Addresses) == 0 {
		return nil, nil //nolint:nilnil
	}

	roption := rueidis.ClientOption{
		InitAddress:           cfg.Addresses,
		Password:              cfg.Password,
		Username:              cfg.Username,
		SelectDB:              cfg.Database,
		ClientName:            fmt.Sprintf("blocky-%s", util.HostnameString()),
		ClientTrackingOptions: []string{"PREFIX", "blocky:", "BCAST"},
	}

	if len(cfg.SentinelMasterSet) > 0 {
		roption.Sentinel = rueidis.SentinelOption{
			Username:  cfg.SentinelUsername,
			Password:  cfg.SentinelPassword,
			MasterSet: cfg.SentinelMasterSet,
		}
	}

	var err error
	var client rueidis.Client
	for i := 0; i < cfg.ConnectionAttempts; i++ {
		client, err = rueidis.NewClient(roption)
		if err == nil {
			break
		}
		time.Sleep(time.Duration(cfg.ConnectionCooldown))
	}
	if err != nil {
		return nil, err
	}

	return client, nil
}
