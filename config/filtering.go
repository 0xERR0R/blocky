package config

import (
	"github.com/sirupsen/logrus"
)

type Filtering struct {
	// DNS query types to drop; matching queries receive an empty answer (e.g. AAAA to block IPv6 lookups).
	QueryTypes QTypeSet `yaml:"queryTypes"`
}

// IsEnabled implements `config.Configurable`.
func (c *Filtering) IsEnabled() bool {
	return len(c.QueryTypes) != 0
}

// LogConfig implements `config.Configurable`.
func (c *Filtering) LogConfig(logger *logrus.Entry) {
	logger.Info("query types:")

	for qType := range c.QueryTypes {
		logger.Infof("  - %s", qType)
	}
}
