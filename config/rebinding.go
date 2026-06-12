package config

import (
	"errors"
	"strings"

	"github.com/sirupsen/logrus"
)

// RebindingProtection drops answers from the general upstream resolvers that contain
// private, loopback, link-local or unspecified IPs (DNS rebinding protection).
type RebindingProtection struct {
	// Enable DNS rebinding protection for answers from the general upstream resolvers.
	Enable bool `yaml:"enable"`
	// Domains (including their subdomains) that may resolve to non-public IPs (split-horizon DNS).
	AllowedDomains []string `yaml:"allowedDomains"`
}

// IsEnabled implements `config.Configurable`.
func (c *RebindingProtection) IsEnabled() bool {
	return c.Enable
}

// LogConfig implements `config.Configurable`.
func (c *RebindingProtection) LogConfig(logger *logrus.Entry) {
	logger.Infof("allowed domains (%d):", len(c.AllowedDomains))

	for _, domain := range c.AllowedDomains {
		logger.Infof("  - %s", domain)
	}
}

// validate returns an error if the allowlist contains an empty entry.
func (c *RebindingProtection) validate() error {
	for _, domain := range c.AllowedDomains {
		if strings.TrimSpace(domain) == "" {
			return errors.New("rebindingProtection.allowedDomains must not contain empty entries")
		}
	}

	return nil
}
