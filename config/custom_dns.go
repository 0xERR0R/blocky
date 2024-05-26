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
	Zone                ZoneFileDNS      `yaml:"zone" default:""`
	FilterUnmappedTypes bool             `yaml:"filterUnmappedTypes" default:"true"`
}

type (
	CustomDNSMapping map[string]CustomDNSEntries
	CustomDNSEntries []dns.RR

	ZoneFileDNS struct {
		RRs        CustomDNSMapping
		configPath string
	}
)

func (z *ZoneFileDNS) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var input string
	if err := unmarshal(&input); err != nil {
		return err
	}

	result := make(CustomDNSMapping)

	zoneParser := dns.NewZoneParser(strings.NewReader(input), "", z.configPath)
	zoneParser.SetIncludeAllowed(true)

	for {
		zoneRR, ok := zoneParser.Next()

		if !ok {
			if zoneParser.Err() != nil {
				return zoneParser.Err()
			}

			// Done
			break
		}

		domain := zoneRR.Header().Name

		if _, ok := result[domain]; !ok {
			result[domain] = make(CustomDNSEntries, 0, 1)
		}

		result[domain] = append(result[domain], zoneRR)
	}

	z.RRs = result

	return nil
}

func (c *CustomDNSEntries) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var input string
	if err := unmarshal(&input); err != nil {
		return err
	}

	parts := strings.Split(input, ",")
	result := make(CustomDNSEntries, len(parts))

	for i, part := range parts {
		rr, err := configToRR(strings.TrimSpace(part))
		if err != nil {
			return err
		}

		result[i] = rr
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

func configToRR(ipStr string) (dns.RR, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address '%s'", ipStr)
	}

	if ip.To4() != nil {
		a := new(dns.A)
		a.A = ip

		return a, nil
	}

	aaaa := new(dns.AAAA)
	aaaa.AAAA = ip

	return aaaa, nil
}
