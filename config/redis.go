package config

import (
	"strings"

	"github.com/sirupsen/logrus"
)

// Redis configuration for the redis connection
type Redis struct {
	Address            string   `yaml:"address"`
	Username           string   `yaml:"username" default:""`
	Password           string   `yaml:"password" default:""`
	Database           int      `yaml:"database" default:"0"`
	Required           bool     `yaml:"required" default:"false"`
	ConnectionAttempts int      `yaml:"connectionAttempts" default:"3"`
	ConnectionCooldown Duration `yaml:"connectionCooldown" default:"1s"`
	SentinelUsername   string   `yaml:"sentinelUsername" default:""`
	SentinelPassword   string   `yaml:"sentinelPassword" default:""`
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
	logger.Info("password: ", obfuscatePassword(c.Password))
	logger.Info("database: ", c.Database)
	logger.Info("required: ", c.Required)
	logger.Info("connectionAttempts: ", c.ConnectionAttempts)
	logger.Info("connectionCooldown: ", c.ConnectionCooldown)

	if len(c.SentinelAddresses) > 0 {
		logger.Info("sentinel:")
		logger.Info("  master: ", c.Address)
		logger.Info("  username: ", c.SentinelUsername)
		logger.Info("  password: ", obfuscatePassword(c.SentinelPassword))
		logger.Info("  addresses:")

		for _, addr := range c.SentinelAddresses {
			logger.Info("    - ", addr)
		}
	}
}

// obfuscatePassword replaces all characters of a password except the first and last with *
func obfuscatePassword(pass string) string {
	return strings.Repeat("*", len(pass))
}
