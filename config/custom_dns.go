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
	containsCNAME := false

	for i, part := range parts {
		rr, err := configToRR(part)
		if err != nil {
			return err
		}

		_, isCNAME := rr.(*dns.CNAME)
		containsCNAME = containsCNAME || isCNAME

		result[i] = rr
	}

	if containsCNAME && len(result) > 1 {
		return fmt.Errorf("when a CNAME record is present, it must be the only record in the mapping")
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

func removePrefixSuffix(in, prefix string) string {
	in = strings.TrimPrefix(in, fmt.Sprintf("%s(", prefix))
	in = strings.TrimSuffix(in, ")")

	return strings.TrimSpace(in)
}

func configToRR(part string) (dns.RR, error) {
	if strings.HasPrefix(part, "CNAME(") {
		domain := removePrefixSuffix(part, "CNAME")
		domain = dns.Fqdn(domain)
		cname := &dns.CNAME{Target: domain}

		return cname, nil
	}

	// Fall back to A/AAAA records to maintain backwards compatibility in config.yml
	// We will still remove the A() or AAAA() if it exists
	if strings.Contains(part, ".") { // IPV4 address
		ipStr := removePrefixSuffix(part, "A")
		ip := net.ParseIP(ipStr)

		if ip == nil {
			return nil, fmt.Errorf("invalid IP address '%s'", part)
		}

		a := new(dns.A)
		a.A = ip

		return a, nil
	} else { // IPV6 address
		ipStr := removePrefixSuffix(part, "AAAA")
		ip := net.ParseIP(ipStr)

		if ip == nil {
			return nil, fmt.Errorf("invalid IP address '%s'", part)
		}

		aaaa := new(dns.AAAA)
		aaaa.AAAA = ip

		return aaaa, nil
	}
}
