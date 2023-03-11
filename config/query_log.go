package config

import (
	"github.com/sirupsen/logrus"
)

// QueryLogConfig configuration for the query logging
type QueryLogConfig struct {
	Target           string          `yaml:"target"`
	Type             QueryLogType    `yaml:"type"`
	LogRetentionDays uint64          `yaml:"logRetentionDays"`
	CreationAttempts int             `yaml:"creationAttempts" default:"3"`
	CreationCooldown Duration        `yaml:"creationCooldown" default:"2s"`
	Fields           []QueryLogField `yaml:"fields"`
}

// IsEnabled implements `config.ValueLogger`.
func (c *QueryLogConfig) IsEnabled() bool {
	return c.Type != QueryLogTypeNone
}

// LogValues implements `config.ValueLogger`.
func (c *QueryLogConfig) LogValues(logger *logrus.Entry) {
	logger.Infof("type: %q", c.Type)
	logger.Infof("target: %q", c.Target)
	logger.Infof("logRetentionDays: %d", c.LogRetentionDays)
	logger.Debugf("creationAttempts: %d", c.CreationAttempts)
	logger.Debugf("creationCooldown: %d", c.CreationCooldown)
}
