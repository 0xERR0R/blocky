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

// IsEnabled implements `config.ValueLogger`.
func (c *ClientLookupConfig) IsEnabled() bool {
	return !c.Upstream.IsDefault() || len(c.ClientnameIPMapping) != 0
}

// LogValues implements `config.ValueLogger`.
func (c *ClientLookupConfig) LogValues(logger *logrus.Entry) {
	logger.Infof("singleNameOrder = \"%v\"", c.SingleNameOrder)

	if !c.Upstream.IsDefault() {
		logger.Infof("upstream = %q", c.Upstream)
	}

	if len(c.ClientnameIPMapping) > 0 {
		logger.Infof("client IP mapping:")

		for k, v := range c.ClientnameIPMapping {
			logger.Infof("%s -> %s", k, v)
		}
	}
}
