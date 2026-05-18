package config

import "github.com/sirupsen/logrus"

// HTTP3 holds DNS-over-HTTPS over HTTP/3 (DoH3) server settings.
type HTTP3 struct {
	Enable bool `default:"false" yaml:"enable"`
}

// IsEnabled implements `config.Configurable`.
func (c *HTTP3) IsEnabled() bool {
	return c.Enable
}

// LogConfig implements `config.Configurable`.
func (c *HTTP3) LogConfig(logger *logrus.Entry) {
	logger.Info("enabled")
}
