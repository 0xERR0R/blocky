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

type (
	CustomDNSMapping map[string]CustomDNSEntries
	CustomDNSEntries []dns.RR
)

func (c *CustomDNSEntries) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var input string
	if err := unmarshal(&input); err != nil {
		return err
	}

	parts := strings.Split(input, ",")
	result := make(CustomDNSEntries, len(parts))

	removePrefixSuffix := func(in, prefix string) string {
		in = strings.TrimPrefix(in, fmt.Sprintf("%s(", prefix))
		in = strings.TrimSuffix(in, ")")

		return strings.TrimSpace(in)
	}

	for _, part := range parts {
		if strings.HasPrefix(part, "CNAME(") {
			domain := removePrefixSuffix(part, "CNAME")
			domain = dns.Fqdn(domain)
			cname := &dns.CNAME{Target: domain}
			result = append(result, cname)
		} else {
			// Fall back to A/AAAA records to maintain backwards compatibility in config.yml
			// We will still remove the A() or AAAA() if it exists
			if strings.Contains(part, ".") { // IPV4 address
				ipStr := removePrefixSuffix(part, "A")
				ip := net.ParseIP(ipStr)

				if ip == nil {
					return fmt.Errorf("invalid IP address '%s'", part)
				}

				a := new(dns.A)
				a.A = ip

				result = append(result, a)
			} else { // IPV6 address
				ipStr := removePrefixSuffix(part, "AAAA")
				ip := net.ParseIP(ipStr)

				if ip == nil {
					return fmt.Errorf("invalid IP address '%s'", part)
				}

				aaaa := new(dns.AAAA)
				aaaa.AAAA = ip

				result = append(result, aaaa)
			}
		}
	}

	*c = result

	return nil
}

// IsEnabled implements `config.Configurable`.
func (c *CustomDNS) IsEnabled() bool {
	return len(c.Mapping) != 0
}

// LogConfig implements `config.Configurable`.
func (c *CustomDNS) LogConfig(logger *logrus.Entry) {
	logger.Debugf("TTL = %s", c.CustomTTL)
	logger.Debugf("filterUnmappedTypes = %t", c.FilterUnmappedTypes)

	logger.Info("mapping:")

	for key, val := range c.Mapping {
		logger.Infof("  %s = %s", key, val)
	}
}
