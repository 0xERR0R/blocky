package config

import "log/slog"

// HTTP3 holds DNS-over-HTTPS over HTTP/3 (DoH3) server settings.
type HTTP3 struct {
	// Enable the HTTP/3 listener on the same addresses as ports.https (requires ports.https to be set).
	Enable bool `default:"false" yaml:"enable"`
}

// IsEnabled implements `config.Configurable`.
func (c *HTTP3) IsEnabled() bool {
	return c.Enable
}

// LogConfig implements `config.Configurable`.
func (c *HTTP3) LogConfig(logger *slog.Logger) {
	logger.Info("enabled")
}
