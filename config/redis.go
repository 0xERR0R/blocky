package config

import (
	"fmt"

	"github.com/0xERR0R/blocky/log"
)

// RedisConfig configuration for the redis connection
type RedisConfig struct {
	Addresses          []string `yaml:"addresses"`
	Username           string   `yaml:"username" default:""`
	Password           string   `yaml:"password" default:""`
	SentinelUsername   string   `yaml:"sentinelUsername" default:""`
	SentinelPassword   string   `yaml:"sentinelPassword" default:""`
	SentinelMasterSet  string   `yaml:"sentinelMasterSet" default:""`
	Database           int      `yaml:"database" default:"0"`
	ConnectionAttempts int      `yaml:"connectionAttempts" default:"3"`
	ConnectionCooldown Duration `yaml:"connectionCooldown" default:"1s"`
	Required           bool     `yaml:"required" default:"false"`
	Address            string   `yaml:"address"`           // Deprecated: use Addresses
	SentinelAddresses  []string `yaml:"sentinelAddresses"` // Deprecated: use Addresses
}

func fixDeprecatedRedis(cfg *Config) error {
	if len(cfg.Redis.Addresses) == 0 && len(cfg.Redis.Address) > 0 {
		log.Log().Warnln("'redis.address' is deprecated. Please use 'redis.addresses' instead.")

		cfg.Redis.Addresses = []string{cfg.Redis.Address}
	} else if len(cfg.Redis.Addresses) == 0 && len(cfg.Redis.SentinelAddresses) > 0 {
		log.Log().Warnln("'redis.sentinelAddresses' is deprecated. Please use 'redis.addresses' instead.")

		cfg.Redis.Addresses = cfg.Redis.SentinelAddresses

		if len(cfg.Redis.SentinelMasterSet) == 0 {
			return fmt.Errorf("'redis.sentinelMasterSet' has to be set if Redis Sentinel is used")
		}
	}

	return nil
}
