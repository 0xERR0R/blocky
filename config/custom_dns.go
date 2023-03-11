package config

import (
	"fmt"
	"net"
	"strings"

	"github.com/sirupsen/logrus"
)

// CustomDNSConfig custom DNS configuration
type CustomDNSConfig struct {
	RewriteConfig       `yaml:",inline"`
	CustomTTL           Duration         `yaml:"customTTL" default:"1h"`
	Mapping             CustomDNSMapping `yaml:"mapping"`
	FilterUnmappedTypes bool             `yaml:"filterUnmappedTypes" default:"true"`
}

// CustomDNSMapping mapping for the custom DNS configuration
type CustomDNSMapping struct {
	HostIPs map[string][]net.IP `yaml:"hostIPs"`
}

// IsEnabled implements `config.ValueLogger`.
func (c *CustomDNSConfig) IsEnabled() bool {
	return len(c.Mapping.HostIPs) != 0
}

// LogValues implements `config.ValueLogger`.
func (c *CustomDNSConfig) LogValues(logger *logrus.Entry) {
	for key, val := range c.Mapping.HostIPs {
		logger.Infof("%s = %q", key, val)
	}

	c.RewriteConfig.LogValues(logger)
}

// UnmarshalYAML implements `yaml.Unmarshaler`.
func (c *CustomDNSMapping) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var input map[string]string
	if err := unmarshal(&input); err != nil {
		return err
	}

	result := make(map[string][]net.IP, len(input))

	for k, v := range input {
		var ips []net.IP

		for _, part := range strings.Split(v, ",") {
			ip := net.ParseIP(strings.TrimSpace(part))
			if ip == nil {
				return fmt.Errorf("invalid IP address '%s'", part)
			}

			ips = append(ips, ip)
		}

		result[k] = ips
	}

	c.HostIPs = result

	return nil
}
