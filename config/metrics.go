package config

import "github.com/sirupsen/logrus"

// Metrics contains the config values for prometheus
type Metrics struct {
	Enable bool   `yaml:"enable" default:"false"`
	Path   string `yaml:"path" default:"/metrics"`
}

// IsEnabled implements `config.Configurable`.
func (c *Metrics) IsEnabled() bool {
	return c.Enable
}

// LogConfig implements `config.Configurable`.
func (c *Metrics) LogConfig(logger *logrus.Entry) {
	logger.Infof("url path: %s", c.Path)
}
