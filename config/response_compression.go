package config

import (
	"errors"
	"net"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
)

// ResponseCompression forces DNS name compression (RFC 1035 §4.1.4) of responses that blocky would
// otherwise send uncompressed because they fit the client's buffer as they are.
//
// Receivers must understand compressed names, but not every client copes with uncompressed ones:
// some embedded stub resolvers were only ever tested against compressing servers and silently
// discard an uncompressed answer.
type ResponseCompression struct {
	// If true, every response is compressed, as blocky did before v0.32.0.
	Always bool `default:"false" yaml:"always"`
	// Clients whose responses are always compressed: IPs, CIDRs or client names (wildcards supported).
	Clients []string `yaml:"clients"`

	clientNets  []*net.IPNet
	clientNames []string
}

// IsEnabled implements `config.Configurable`.
func (c *ResponseCompression) IsEnabled() bool {
	return c.Always || len(c.Clients) > 0
}

// LogConfig implements `config.Configurable`.
func (c *ResponseCompression) LogConfig(logger *logrus.Entry) {
	logger.Infof("always  = %t", c.Always)
	logger.Infof("clients = %v", c.Clients)
}

func (c *ResponseCompression) validate() error {
	c.clientNets = nil
	c.clientNames = nil

	for _, client := range c.Clients {
		client = strings.TrimSpace(client)
		if client == "" {
			return errors.New("responseCompression: clients must not contain empty entries")
		}

		if ipNet, err := parseCIDRorIP(client); err == nil {
			c.clientNets = append(c.clientNets, ipNet)

			continue
		}

		c.clientNames = append(c.clientNames, strings.ToLower(client))
	}

	return nil
}

// ValidateForTest exposes validate for cross-package tests.
// Internal package callers should use the unexported validate.
func (c *ResponseCompression) ValidateForTest() error { return c.validate() }

// ForceFor reports whether the response to a client with the given IP and names must be compressed.
func (c *ResponseCompression) ForceFor(clientIP net.IP, clientNames []string) bool {
	return c.Always || c.matchesClient(clientIP, clientNames)
}

func (c *ResponseCompression) matchesClient(clientIP net.IP, clientNames []string) bool {
	if clientIP != nil {
		for _, ipNet := range c.clientNets {
			if ipNet.Contains(clientIP) {
				return true
			}
		}
	}

	for _, name := range clientNames {
		lowerName := strings.ToLower(name)

		for _, pattern := range c.clientNames {
			if matched, _ := filepath.Match(pattern, lowerName); matched {
				return true
			}
		}
	}

	return false
}
