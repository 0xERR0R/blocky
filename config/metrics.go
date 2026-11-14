package config

import "github.com/sirupsen/logrus"

// Metrics contains the config values for prometheus
type Metrics struct {
	// If true, enables the Prometheus metrics endpoint.
	Enable bool `default:"false" yaml:"enable"`
	// URL path under which the Prometheus metrics are served.
	Path string `default:"/metrics" yaml:"path"`
	// If true, the client name (or IP) is used as the "client" label on
	// blocky_query_total and blocky_client_response_total. Disable to collapse the
	// label to a single "unknown" value and avoid unbounded metric cardinality when
	// blocky serves many distinct or client-controlled names (e.g. an internet-facing DoH).
	EnableClientLabel bool `default:"true" yaml:"enableClientLabel"`
}

// IsEnabled implements `config.Configurable`.
func (c *Metrics) IsEnabled() bool {
	return c.Enable
}

// LogConfig implements `config.Configurable`.
func (c *Metrics) LogConfig(logger *logrus.Entry) {
	logger.Infof("url path: %s", c.Path)
	logger.Infof("enable client label: %t", c.EnableClientLabel)
}
