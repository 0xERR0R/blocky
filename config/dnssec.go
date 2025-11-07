package config

import (
	"github.com/sirupsen/logrus"
)

// DNSSEC is the configuration for DNSSEC validation
type DNSSEC struct {
	Validate             bool     `default:"false"     yaml:"validate"`
	TrustAnchors         []string `yaml:"trustAnchors"`
	MaxChainDepth        uint     `default:"10"        yaml:"maxChainDepth"`
	CacheExpirationHours uint     `default:"1"         yaml:"cacheExpirationHours"`
	MaxNSEC3Iterations   uint     `default:"150"       yaml:"maxNSEC3Iterations"` // RFC 5155 §10.3
	// DoS protection: max upstream queries per validation
	MaxUpstreamQueries uint `default:"30" yaml:"maxUpstreamQueries"`
	// Clock skew tolerance in seconds for signature validation (default: 3600 = 1 hour)
	// Allows validation to succeed even if system clock is off by this amount.
	// Matches Unbound/BIND defaults for real-world deployments (VMs, containers, embedded systems).
	// Per RFC 6781 §4.1.2: Validators should account for clock skew in deployment environments.
	ClockSkewToleranceSec uint `default:"3600" yaml:"clockSkewToleranceSec"`
}

// IsEnabled returns true if DNSSEC validation is enabled
func (c *DNSSEC) IsEnabled() bool {
	return c.Validate
}

// LogConfig logs the DNSSEC configuration
func (c *DNSSEC) LogConfig(logger *logrus.Entry) {
	logger.Infof("Validation = %t", c.Validate)

	if c.Validate {
		if len(c.TrustAnchors) > 0 {
			logger.Infof("Custom trust anchors = %d", len(c.TrustAnchors))
		} else {
			logger.Info("Using default root trust anchors")
		}
		logger.Infof("Max chain depth = %d", c.MaxChainDepth)
		logger.Infof("Cache expiration = %d hour(s)", c.CacheExpirationHours)
		logger.Infof("Max NSEC3 iterations = %d", c.MaxNSEC3Iterations)
		logger.Infof("Max upstream queries per validation = %d", c.MaxUpstreamQueries)
		logger.Infof("Clock skew tolerance = %d second(s)", c.ClockSkewToleranceSec)
	}
}
