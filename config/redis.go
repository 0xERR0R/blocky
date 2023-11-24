package config

import (
	"regexp"

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
		logger.Info("Address: ", c.Address)
	}

	logger.Info("Username: ", c.Username)
	logger.Info("Password: ", obfuscatePassword(c.Password))
	logger.Info("Database: ", c.Database)
	logger.Info("Required: ", c.Required)
	logger.Info("ConnectionAttempts: ", c.ConnectionAttempts)
	logger.Info("ConnectionCooldown: ", c.ConnectionCooldown)

	if len(c.SentinelAddresses) > 0 {
		logger.Info("Sentinel:")
		logger.Info("  MasterName: ", c.Address)
		logger.Info("  Username: ", c.SentinelUsername)
		logger.Info("  Password: ", obfuscatePassword(c.SentinelPassword))
		logger.Info("  Addresses:")

		for _, addr := range c.SentinelAddresses {
			logger.Info("    - ", addr)
		}
	}
}

// obfuscatePassword replaces all characters of a password except the first and last with *
func obfuscatePassword(pass string) string {
	if pass == "" {
		return ""
	}

	re := regexp.MustCompile(`^(.).*(.)$`)

	return re.ReplaceAllString(pass, `$1*****$2`)
}
