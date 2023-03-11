package config

import (
	"net"

	"github.com/sirupsen/logrus"
)

// ClientLookupConfig configuration for the client lookup
type ClientLookupConfig struct {
	ClientnameIPMapping map[string][]net.IP `yaml:"clients"`
	Upstream            Upstream            `yaml:"upstream"`
	SingleNameOrder     []uint              `yaml:"singleNameOrder"`
}

// IsEnabled implements `config.Configurable`.
func (c *ClientLookupConfig) IsEnabled() bool {
	return !c.Upstream.IsDefault() || len(c.ClientnameIPMapping) != 0
}

// LogConfig implements `config.Configurable`.
func (c *ClientLookupConfig) LogConfig(logger *logrus.Entry) {
	if !c.Upstream.IsDefault() {
		logger.Infof("upstream = %s", c.Upstream)
	}

	logger.Infof("singleNameOrder = %v", c.SingleNameOrder)

	if len(c.ClientnameIPMapping) > 0 {
		logger.Infof("client IP mapping:")

		for k, v := range c.ClientnameIPMapping {
			logger.Infof("  %s = %s", k, v)
		}
	}
}
