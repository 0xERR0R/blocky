package config

import (
	"fmt"
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

// validate returns an error if the allowlist contains an empty or non-plain-domain
// entry. It runs even when the protection is disabled, so config errors surface
// before the user enables it.
func (c *RebindingProtection) validate() error {
	for i, domain := range c.AllowedDomains {
		trimmed := strings.TrimSpace(domain)
		if trimmed == "" {
			return fmt.Errorf("rebindingProtection.allowedDomains[%d] must not be empty", i)
		}

		// queryLog.ignore.domains supports wildcard/regex syntax; this list does not —
		// reject such entries instead of silently never matching them
		if strings.ContainsAny(trimmed, "*/ \t") {
			return fmt.Errorf(
				"rebindingProtection.allowedDomains[%d] (%q) must be a plain domain (no wildcards, regexes or whitespace); subdomains match automatically",
				i, domain)
		}
	}

	return nil
}
