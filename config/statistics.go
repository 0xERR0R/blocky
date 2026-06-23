package config

import "log/slog"

// Statistics contains the config for the in-memory statistics subsystem.
type Statistics struct {
	// If true, enables in-memory statistics collection and the /api/stats endpoint.
	Enable bool `default:"false" yaml:"enable"`
}

// IsEnabled implements `config.Configurable`.
func (c *Statistics) IsEnabled() bool {
	return c.Enable
}

// LogConfig implements `config.Configurable`.
func (c *Statistics) LogConfig(logger *slog.Logger) {
	logger.Info("enable", slog.Bool("enable", c.Enable))
}
