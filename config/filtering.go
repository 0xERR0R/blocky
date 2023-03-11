package config

import (
	"github.com/sirupsen/logrus"
)

type FilteringConfig struct {
	QueryTypes QTypeSet `yaml:"queryTypes"`
}

// IsEnabled implements `config.ValueLogger`.
func (c *FilteringConfig) IsEnabled() bool {
	return len(c.QueryTypes) != 0
}

// LogValues implements `config.ValueLogger`.
func (c *FilteringConfig) LogValues(logger *logrus.Entry) {
	logger.Info("filtering query Types:")

	for qType := range c.QueryTypes {
		logger.Infof("  - %s", qType)
	}
}
