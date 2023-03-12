package config

import (
	"github.com/sirupsen/logrus"
)

type FilteringConfig struct {
	QueryTypes QTypeSet `yaml:"queryTypes"`
}

// IsEnabled implements `config.Configurable`.
func (c *FilteringConfig) IsEnabled() bool {
	return len(c.QueryTypes) != 0
}

// LogConfig implements `config.Configurable`.
func (c *FilteringConfig) LogConfig(logger *logrus.Entry) {
	logger.Info("query types:")

	for qType := range c.QueryTypes {
		logger.Infof("  - %s", qType)
	}
}
