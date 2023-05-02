package config

import (
	"fmt"

	"github.com/0xERR0R/blocky/log"
	"github.com/rueian/rueidis"
	"github.com/sirupsen/logrus"
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

func (c *RedisConfig) GetClientOptions() *rueidis.ClientOption {
	res := rueidis.ClientOption{
		InitAddress:           c.Addresses,
		Password:              c.Password,
		Username:              c.Username,
		SelectDB:              c.Database,
		RingScaleEachConn:     c.ConnRingScale,
		CacheSizeEachConn:     c.LocalCacheSize,
		ClientTrackingOptions: []string{"PREFIX", "blocky:", "BCAST"},
	}

	if len(c.SentinelMasterSet) > 0 {
		res.Sentinel = rueidis.SentinelOption{
			Username:  c.SentinelUsername,
			Password:  c.SentinelPassword,
			MasterSet: c.SentinelMasterSet,
		}
	}

	return &res
}

// IsEnabled implements `config.Configurable`.
func (c *RedisConfig) IsEnabled() bool {
	return len(c.Addresses) > 0
}

// LogConfig implements `config.Configurable`.
func (c *RedisConfig) LogConfig(logger *logrus.Entry) {
	logger.Info("addresses:")

	for _, a := range c.Addresses {
		logger.Infof("  - %s", a)
	}
}

func (c *RedisConfig) validateConfig() error {
	if len(c.Addresses) == 0 && len(c.SentinelAddresses) > 0 {
		log.Log().Warnln("'redis.sentinelAddresses' is deprecated. Please use 'redis.addresses' instead.")

		c.Addresses = c.SentinelAddresses
	} else if len(c.Addresses) == 0 && len(c.Address) > 0 {
		log.Log().Warnln("'redis.address' is deprecated. Please use 'redis.addresses' instead.")

		c.Addresses = []string{c.Address}
	}

	if (len(c.SentinelUsername) > 0 ||
		len(c.SentinelPassword) > 0 ||
		len(c.SentinelAddresses) > 0) &&
		len(c.SentinelMasterSet) == 0 {
		return fmt.Errorf("'redis.sentinelMasterSet' has to be set if Redis Sentinel is used")
	}

	return nil
}
