package config

import (
	"fmt"

	"github.com/0xERR0R/blocky/log"
	"github.com/rueian/rueidis"
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
	ConnRingScale      int      `yaml:"connRingScale" default:"10"`
	ShuffleInit        bool     `yaml:"shuffleInit" default:"false"`
	LocalCacheTime     Duration `yaml:"localCacheTime" default:"10m"`
	LocalCacheSize     int      `yaml:"localCacheSize" default:"1048576"`
	Required           bool     `yaml:"required" default:"false"` // Deprecated: always required if enabled
	Address            string   `yaml:"address"`                  // Deprecated: use Addresses
	SentinelAddresses  []string `yaml:"sentinelAddresses"`        // Deprecated: use Addresses
}

func (cfg *RedisConfig) GetClientOptions() *rueidis.ClientOption {
	res := rueidis.ClientOption{
		InitAddress:           cfg.Addresses,
		Password:              cfg.Password,
		Username:              cfg.Username,
		SelectDB:              cfg.Database,
		RingScaleEachConn:     cfg.ConnRingScale,
		CacheSizeEachConn:     cfg.LocalCacheSize,
		ClientTrackingOptions: []string{"PREFIX", "blocky:", "BCAST"},
	}

	if len(cfg.SentinelMasterSet) > 0 {
		res.Sentinel = rueidis.SentinelOption{
			Username:  cfg.SentinelUsername,
			Password:  cfg.SentinelPassword,
			MasterSet: cfg.SentinelMasterSet,
		}
	}

	return &res
}

func fixDeprecatedRedis(cfg *Config) {
	if len(cfg.Redis.Addresses) == 0 && len(cfg.Redis.SentinelAddresses) > 0 {
		log.Log().Warnln("'redis.sentinelAddresses' is deprecated. Please use 'redis.addresses' instead.")

		cfg.Redis.Addresses = cfg.Redis.SentinelAddresses
	} else if len(cfg.Redis.Addresses) == 0 && len(cfg.Redis.Address) > 0 {
		log.Log().Warnln("'redis.address' is deprecated. Please use 'redis.addresses' instead.")

		cfg.Redis.Addresses = []string{cfg.Redis.Address}
	}
}

func validateRedisConfig(cfg *Config) error {
	if (len(cfg.Redis.SentinelUsername) > 0 ||
		len(cfg.Redis.SentinelPassword) > 0 ||
		len(cfg.Redis.SentinelAddresses) > 0) &&
		len(cfg.Redis.SentinelMasterSet) == 0 {
		return fmt.Errorf("'redis.sentinelMasterSet' has to be set if Redis Sentinel is used")
	}

	return nil
}
