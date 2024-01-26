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

	removePrefixSuffix := func(in, prefix string) string {
		in = strings.TrimPrefix(in, fmt.Sprintf("%s(", prefix))
		in = strings.TrimSuffix(in, ")")

		return strings.TrimSpace(in)
	}

	addMapping := func(domain string, rr dns.RR) {
		if _, ok := result[domain]; !ok {
			result[domain] = []dns.RR{rr}
		} else {
			result[domain] = append(result[domain], rr)
		}
	}

	for k, v := range input {
		for _, part := range strings.Split(v, ",") {
			if strings.HasPrefix(part, "CNAME(") {
				domain := removePrefixSuffix(part, "CNAME")
				domain = dns.Fqdn(domain)
				cname := &dns.CNAME{Target: domain}
				addMapping(k, cname)
			} else {
				// Fall back to A/AAAA records to maintain backwards compatibility in config.yml
				// We will still remove the A() or AAAA() if it exists
				if strings.Contains(part, ".") { // IPV4 address
					ipStr := removePrefixSuffix(part, "A")
					ip := net.ParseIP(ipStr)

					if ip == nil {
						return fmt.Errorf("inpartalid IP address '%s'", part)
					}

					a := new(dns.A)
					a.A = ip

					addMapping(k, a)
				} else { // IPV6 address
					ipStr := removePrefixSuffix(part, "AAAA")
					ip := net.ParseIP(ipStr)

					if ip == nil {
						return fmt.Errorf("inpartalid IP address '%s'", part)
					}

					aaaa := new(dns.AAAA)
					aaaa.AAAA = ip

					addMapping(k, aaaa)
				}
			}
		}
	}

	c.Entries = result

	return nil
}
