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

// SetDefaults implements `defaults.Setter`.
func (c *QueryLogConfig) SetDefaults() {
	// Since the default depends on the enum values, set it dynamically
	// to avoid having to repeat the values in the annotation.
	c.Fields = QueryLogFieldValues()
}

// IsEnabled implements `config.Configurable`.
func (c *QueryLogConfig) IsEnabled() bool {
	return c.Type != QueryLogTypeNone
}

// LogConfig implements `config.Configurable`.
func (c *QueryLogConfig) LogConfig(logger *logrus.Entry) {
	logger.Infof("type: %s", c.Type)

	if c.Target != "" {
		logger.Infof("target: %s", c.Target)
	}

	logger.Infof("logRetentionDays: %d", c.LogRetentionDays)
	logger.Debugf("creationAttempts: %d", c.CreationAttempts)
	logger.Debugf("creationCooldown: %s", c.CreationCooldown)
	logger.Infof("fields: %s", c.Fields)
}
