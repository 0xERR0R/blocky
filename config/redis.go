package config

import (
	"github.com/sirupsen/logrus"
)

// Redis configuration for the redis connection
type Redis struct {
	Address            string   `yaml:"address"`
	Username           string   `default:""               yaml:"username"`
	Password           string   `default:""               yaml:"password"`
	Database           int      `default:"0"              yaml:"database"`
	Required           bool     `default:"false"          yaml:"required"`
	ConnectionAttempts int      `default:"3"              yaml:"connectionAttempts"`
	ConnectionCooldown Duration `default:"1s"             yaml:"connectionCooldown"`
	SentinelUsername   string   `default:""               yaml:"sentinelUsername"`
	SentinelPassword   string   `default:""               yaml:"sentinelPassword"`
	SentinelAddresses  []string `yaml:"sentinelAddresses"`
}

// IsEnabled implements `config.Configurable`
func (c *Redis) IsEnabled() bool {
	return c.Address != ""
}

// LogConfig implements `config.Configurable`
func (c *Redis) LogConfig(logger *logrus.Entry) {
	if len(c.SentinelAddresses) == 0 {
		logger.Info("address: ", c.Address)
	}

	logger.Info("username: ", c.Username)
	logger.Info("password: ", secretObfuscator)
	logger.Info("database: ", c.Database)
	logger.Info("required: ", c.Required)
	logger.Info("connectionAttempts: ", c.ConnectionAttempts)
	logger.Info("connectionCooldown: ", c.ConnectionCooldown)

	if len(c.SentinelAddresses) > 0 {
		logger.Info("sentinel:")
		logger.Info("  master: ", c.Address)
		logger.Info("  username: ", c.SentinelUsername)
		logger.Info("  password: ", secretObfuscator)
		logger.Info("  addresses:")

		for _, addr := range c.SentinelAddresses {
			logger.Info("    - ", addr)
		}
	}
}
