package config

import (
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
)

// RateLimit configures per-client rate limiting at the head of the resolver chain.
type RateLimit struct {
	Enable     bool     `default:"false" yaml:"enable"`
	Rate       uint     `default:"0"     yaml:"rate"`
	Burst      uint     `default:"0"     yaml:"burst"`
	IPv4Prefix uint8    `default:"32"    yaml:"ipv4Prefix"`
	IPv6Prefix uint8    `default:"64"    yaml:"ipv6Prefix"`
	Allowlist  []string `                yaml:"allowlist"`

	parsedAllowlist []*net.IPNet
}

// IsEnabled implements `config.Configurable`.
func (c *RateLimit) IsEnabled() bool { return c.Enable }

// LogConfig implements `config.Configurable`.
func (c *RateLimit) LogConfig(logger *logrus.Entry) {
	logger.Infof("rate         = %d qps", c.Rate)
	logger.Infof("burst        = %d", c.Burst)
	logger.Infof("ipv4 prefix  = /%d", c.IPv4Prefix)
	logger.Infof("ipv6 prefix  = /%d", c.IPv6Prefix)
	logger.Infof("allowlist    = %v", c.Allowlist)
}

func (c *RateLimit) validate() error {
	if !c.Enable {
		return nil
	}
	if c.Rate == 0 {
		return fmt.Errorf("rateLimit: rate must be > 0 when enabled")
	}
	if c.Burst < c.Rate {
		return fmt.Errorf("rateLimit: burst (%d) must be >= rate (%d)", c.Burst, c.Rate)
	}
	if c.IPv4Prefix > 32 {
		return fmt.Errorf("rateLimit: ipv4Prefix (%d) must be in [0, 32]", c.IPv4Prefix)
	}
	if c.IPv6Prefix > 128 {
		return fmt.Errorf("rateLimit: ipv6Prefix (%d) must be in [0, 128]", c.IPv6Prefix)
	}
	parsed := make([]*net.IPNet, 0, len(c.Allowlist))
	for _, s := range c.Allowlist {
		ipNet, err := parseCIDRorIP(s)
		if err != nil {
			return fmt.Errorf("rateLimit: allowlist entry %q: %w", s, err)
		}
		parsed = append(parsed, ipNet)
	}
	c.parsedAllowlist = parsed
	return nil
}

// ValidateForTest exposes validate for cross-package tests.
// Internal package callers should use the unexported validate.
func (c *RateLimit) ValidateForTest() error { return c.validate() }

// ParsedAllowlist returns the parsed CIDR list populated by validate.
func (c *RateLimit) ParsedAllowlist() []*net.IPNet { return c.parsedAllowlist }

func parseCIDRorIP(s string) (*net.IPNet, error) {
	if _, ipNet, err := net.ParseCIDR(s); err == nil {
		return ipNet, nil
	}
	if ip := net.ParseIP(s); ip != nil {
		bits := 128
		if v4 := ip.To4(); v4 != nil {
			ip = v4
			bits = 32
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
	}
	return nil, fmt.Errorf("not a valid CIDR or IP: %q", s)
}
