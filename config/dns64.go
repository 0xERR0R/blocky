package config

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// DNS64 is the configuration for DNS64 resolver
type DNS64 struct {
	Enable       bool           `default:"false"     yaml:"enable"`
	Prefixes     []netip.Prefix `yaml:"prefixes"`
	ExclusionSet []netip.Prefix `yaml:"exclusionSet"`
}

// IsEnabled implements `config.Configurable`.
func (c *DNS64) IsEnabled() bool {
	return c.Enable
}

// LogConfig implements `config.Configurable`.
func (c *DNS64) LogConfig(logger *logrus.Entry) {
	if len(c.Prefixes) == 0 {
		logger.Info("prefixes: [64:ff9b::/96] (default)")
	} else {
		logger.Info("prefixes:")
		for _, prefix := range c.Prefixes {
			logger.Infof("  - %s", prefix.String())
		}
	}

	if len(c.ExclusionSet) == 0 {
		logger.Info("exclusionSet: [::ffff:0:0/96, ::1/128, fe80::/10] (default, plus configured prefixes)")
	} else {
		logger.Info("exclusionSet (custom):")
		for _, prefix := range c.ExclusionSet {
			logger.Infof("  - %s", prefix.String())
		}
	}
}

// validate checks DNS64 configuration for conflicts and validity
func (c *DNS64) validate(logger *logrus.Entry, filtering *Filtering, caching *Caching) error {
	if !c.Enable {
		return nil
	}

	// Check for AAAA filtering conflict
	if filtering.QueryTypes.Contains(dns.Type(dns.TypeAAAA)) {
		return errors.New("DNS64 will have no effect when filtering.queryTypes contains AAAA " +
			"(all AAAA queries are filtered before reaching DNS64)")
	}

	// Validate prefix lengths and IPv6
	validLengths := map[int]bool{32: true, 40: true, 48: true, 56: true, 64: true, 96: true}
	for _, prefix := range c.Prefixes {
		// Validate it's an IPv6 prefix (not IPv4)
		if !prefix.Addr().Is6() {
			return fmt.Errorf("DNS64 prefix %s is not an IPv6 prefix (IPv4 prefixes not supported)", prefix)
		}

		// Validate prefix length
		bits := prefix.Bits()
		if !validLengths[bits] {
			return fmt.Errorf("DNS64 prefix %s has invalid length /%d. Valid lengths: /32, /40, /48, /56, /64, /96",
				prefix, bits)
		}
	}

	// Validate no prefix overlap
	for i := 0; i < len(c.Prefixes); i++ {
		for j := i + 1; j < len(c.Prefixes); j++ {
			if c.Prefixes[i].Overlaps(c.Prefixes[j]) {
				return fmt.Errorf("DNS64 prefixes %s and %s overlap", c.Prefixes[i], c.Prefixes[j])
			}
		}
	}

	// Validate exclusion set (if configured)
	for _, prefix := range c.ExclusionSet {
		// Validate it's an IPv6 prefix (not IPv4)
		if !prefix.Addr().Is6() {
			return fmt.Errorf("DNS64 exclusion set prefix %s is not an IPv6 prefix (IPv4 prefixes not supported)",
				prefix)
		}
	}

	if c.Enable && !caching.IsEnabled() {
		logger.Warn("DNS64 is enabled but caching is disabled. " +
			"This may result in reduced performance due to additional upstream queries for each synthesis.")
	}

	return nil
}
