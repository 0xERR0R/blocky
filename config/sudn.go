package config

import (
	"github.com/sirupsen/logrus"
)

// SUDN configuration for Special Use Domain Names
type SUDN struct {
	// These are "recommended for private use" but not mandatory.
	// If a user wishes to use one, it will most likely be via conditional
	// upstream or custom DNS, which come before SUDN in the resolver chain.
	// Thus defaulting to `true` and returning NXDOMAIN here should not conflict.
	RFC6762AppendixG bool `yaml:"rfc6762-appendixG" default:"true"`
}

// IsEnabled implements `config.Configurable`.
func (c *SUDN) IsEnabled() bool {
	// The Special Use RFCs are always active
	return true
}

// LogConfig implements `config.Configurable`.
func (c *SUDN) LogConfig(logger *logrus.Entry) {
	logger.Debugf("rfc6762-appendixG = %v", c.RFC6762AppendixG)
}
