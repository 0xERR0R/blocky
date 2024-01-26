package config

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// CustomDNS custom DNS configuration
type CustomDNS struct {
	RewriterConfig      `yaml:",inline"`
	CustomTTL           Duration         `yaml:"customTTL" default:"1h"`
	Mapping             CustomDNSMapping `yaml:"mapping"`
	FilterUnmappedTypes bool             `yaml:"filterUnmappedTypes" default:"true"`
}

type CustomDNSMapping struct {
	Entries map[string][]dns.RR `yaml:"entries"`
}

// IsEnabled implements `config.Configurable`.
func (c *CustomDNS) IsEnabled() bool {
	return len(c.Mapping.Entries) != 0
}

// LogConfig implements `config.Configurable`.
func (c *CustomDNS) LogConfig(logger *logrus.Entry) {
	logger.Debugf("TTL = %s", c.CustomTTL)
	logger.Debugf("filterUnmappedTypes = %t", c.FilterUnmappedTypes)

	logger.Info("mapping:")

	for key, val := range c.Mapping.Entries {
		logger.Infof("  %s = %s", key, val)
	}
}

// UnmarshalYAML implements `yaml.Unmarshaler`.
func (c *CustomDNSMapping) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var input map[string]string
	if err := unmarshal(&input); err != nil {
		return err
	}
	result := make(map[string][]dns.RR, len(input))

	for k, v := range input {
		for _, part := range strings.Split(v, ",") {
			if strings.HasPrefix(v, "CNAME:") {
				domain := strings.TrimSpace(strings.TrimPrefix(v, "CNAME:"))
				domain = dns.Fqdn(domain)
				cname := &dns.CNAME{Target: domain}

				if _, ok := result[k]; !ok {
					result[k] = []dns.RR{cname}
				} else {
					result[k] = append(result[k], cname)
				}
			} else {
				v = strings.TrimPrefix(v, "A:")
				ip := net.ParseIP(strings.TrimSpace(v))

				if ip == nil {
					return fmt.Errorf("invalid IP address '%s'", part)
				}

				a := new(dns.A)
				a.A = ip

				if _, ok := result[k]; !ok {
					result[k] = []dns.RR{a}
				} else {
					result[k] = append(result[k], a)
				}
			}
		}
	}

	c.Entries = result

	return nil
}
