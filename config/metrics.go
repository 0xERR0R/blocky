package config

import "github.com/sirupsen/logrus"

// MetricsConfig contains the config values for prometheus
type MetricsConfig struct {
	Enable bool   `yaml:"enable" default:"false"`
	Path   string `yaml:"path" default:"/metrics"`
}

// IsEnabled implements `config.Configurable`.
func (c *MetricsConfig) IsEnabled() bool {
	return c.Enable
}

// LogConfig implements `config.Configurable`.
func (c *MetricsConfig) LogConfig(logger *logrus.Entry) {
	logger.Infof("url path: %s", c.Path)
}
