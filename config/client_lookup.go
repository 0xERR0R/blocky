package config

import (
	"fmt"
	"log/slog"
	"net"
)

// ClientLookup configuration for the client lookup
type ClientLookup struct {
	// Static map of client name to one or more IP addresses for manual client name assignment.
	ClientnameIPMapping map[string][]net.IP `yaml:"clients"`
	// Upstream DNS server used for rDNS client name lookups (typically your router).
	Upstream Upstream `yaml:"upstream"`
	// Order of preference when a router returns multiple names for a client (1-based index).
	SingleNameOrder []uint `yaml:"singleNameOrder"`
}

// IsEnabled implements `config.Configurable`.
func (c *ClientLookup) IsEnabled() bool {
	return !c.Upstream.IsDefault() || len(c.ClientnameIPMapping) != 0
}

// LogConfig implements `config.Configurable`.
func (c *ClientLookup) LogConfig(logger *slog.Logger) {
	if !c.Upstream.IsDefault() {
		logger.Info(fmt.Sprintf("upstream = %s", c.Upstream))
	}

	logger.Info(fmt.Sprintf("singleNameOrder = %v", c.SingleNameOrder))

	if len(c.ClientnameIPMapping) > 0 {
		logger.Info("client IP mapping:")

		for k, v := range c.ClientnameIPMapping {
			logger.Info(fmt.Sprintf("  %s = %s", k, v))
		}
	}
}
