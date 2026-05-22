package config

import "github.com/sirupsen/logrus"

// Metrics contains the config values for prometheus
type Metrics struct {
	// If true, enables the Prometheus metrics endpoint.
	Enable bool `default:"false" yaml:"enable"`
	// URL path under which the Prometheus metrics are served.
	Path string `default:"/metrics" yaml:"path"`
}

// IsEnabled implements `config.Configurable`.
func (c *Metrics) IsEnabled() bool {
	return c.Enable
}

// LogConfig implements `config.Configurable`.
func (c *Metrics) LogConfig(logger *logrus.Entry) {
	logger.Infof("url path: %s", c.Path)
}
