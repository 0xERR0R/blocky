package config

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"path/filepath"
	"slices"
	"strings"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// CustomDNS custom DNS configuration
type CustomDNS struct {
	RewriterConfig `yaml:",inline"`

	// TTL for DNS records defined in the mapping section (does not apply to zone file records).
	CustomTTL Duration `default:"1h" yaml:"customTTL"`
	// Simple domain-to-IP mappings; multiple IPs per domain separated by commas.
	Mapping CustomDNSMapping `yaml:"mapping"`
	// Per-client domain-to-IP mappings, keyed by client name (wildcards allowed), IP or CIDR
	// (several separated by commas). Only the client's most specific entry applies; for each
	// name of the subdomain walk it is checked before mapping.
	ClientMapping CustomDNSClientMapping `yaml:"clientMapping"`
	// DNS zone file content for more complex record definitions (A, AAAA, CNAME, TXT, SRV, HTTPS, SVCB).
	Zone ZoneFileDNS `default:"" yaml:"zone"`
	// If true, queries for types not defined for a domain return empty; if false, they are forwarded upstream.
	FilterUnmappedTypes bool `default:"true" yaml:"filterUnmappedTypes"`
}

type (
	CustomDNSMapping       map[string]CustomDNSEntries
	CustomDNSEntries       []dns.RR
	CustomDNSClientMapping map[string]CustomDNSMapping

	ZoneFileDNS struct {
		RRs        CustomDNSMapping
		configPath string
	}
)

func (z *ZoneFileDNS) UnmarshalYAML(unmarshal func(any) error) error {
	var input string
	if err := unmarshal(&input); err != nil {
		return fmt.Errorf("failed to unmarshal zone file DNS: %w", err)
	}

	result := make(CustomDNSMapping)

	zoneParser := dns.NewZoneParser(strings.NewReader(input), "", z.configPath)
	zoneParser.SetIncludeAllowed(true)

	for {
		zoneRR, ok := zoneParser.Next()

		if !ok {
			if zoneParser.Err() != nil {
				return fmt.Errorf("zone file parsing error: %w", zoneParser.Err())
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

func (c *CustomDNSEntries) UnmarshalYAML(unmarshal func(any) error) error {
	var input string
	if err := unmarshal(&input); err != nil {
		return fmt.Errorf("failed to unmarshal custom DNS entries: %w", err)
	}

	parts := strings.Split(input, ",")
	result := make(CustomDNSEntries, len(parts))

	for i, part := range parts {
		rr, err := configToRR(strings.TrimSpace(part))
		if err != nil {
			return fmt.Errorf("invalid custom DNS entry '%s': %w", part, err)
		}

		result[i] = rr
	}

	*c = result

	return nil
}

// IsEnabled implements `config.Configurable`.
func (c *CustomDNS) IsEnabled() bool {
	return len(c.Mapping) != 0 || len(c.ClientMapping) != 0
}

// LogConfig implements `config.Configurable`.
func (c *CustomDNS) LogConfig(logger *logrus.Entry) {
	logger.Debugf("TTL = %s", c.CustomTTL)
	logger.Debugf("filterUnmappedTypes = %t", c.FilterUnmappedTypes)

	logger.Info("mapping:")

	for key, val := range c.Mapping {
		logger.Infof("  %s = %s", key, val)
	}

	if len(c.ClientMapping) == 0 {
		return
	}

	logger.Info("clientMapping:")

	for _, client := range slices.Sorted(maps.Keys(c.ClientMapping)) {
		logger.Infof("  %s:", client)

		mapping := c.ClientMapping[client]
		for _, key := range slices.Sorted(maps.Keys(mapping)) {
			logger.Infof("    %s = %s", key, mapping[key])
		}
	}
}

// validate rejects clientMapping keys that cannot match a client, and a client
// identifier listed under more than one key: the client would have two entries of
// equal precedence.
func (c *CustomDNS) validate() error {
	owner := make(map[string]string)

	for _, key := range slices.Sorted(maps.Keys(c.ClientMapping)) {
		ids, err := ParseClientIdentifiers(key)
		if err != nil {
			return fmt.Errorf("customDNS.clientMapping '%s': %w", key, err)
		}

		for _, id := range ids {
			if other, found := owner[id]; found {
				return fmt.Errorf("customDNS.clientMapping: client '%s' is listed under both '%s' and '%s'", id, other, key)
			}

			owner[id] = key
		}
	}

	return nil
}

// ParseClientIdentifiers splits a comma-separated clientMapping key into
// normalized client identifiers: lower case, IPs and CIDRs in canonical form. It
// returns the identifiers it could parse and an error for the first one it
// could not: an IP or CIDR that does not parse, an invalid wildcard pattern, an
// empty identifier, or "default" (mapping already applies to every client).
func ParseClientIdentifiers(key string) ([]string, error) {
	var (
		ids      []string
		firstErr error
	)

	for part := range strings.SplitSeq(key, ",") {
		id, err := parseClientIdentifier(strings.ToLower(strings.TrimSpace(part)))
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}

			continue
		}

		ids = append(ids, id)
	}

	return ids, firstErr
}

// defaultClient is the identifier that stands for every other client in
// clientGroupsBlock.
const defaultClient = "default"

func parseClientIdentifier(id string) (string, error) {
	switch {
	case id == "":
		return "", errors.New("empty client identifier")
	case id == defaultClient:
		return "", errors.New("'default' is not a client: use customDNS.mapping for every client")
	case strings.Contains(id, "/"):
		_, ipNet, err := net.ParseCIDR(id)
		if err != nil {
			return "", fmt.Errorf("invalid CIDR '%s'", id)
		}

		return ipNet.String(), nil
	case strings.Contains(id, ":") || (strings.Contains(id, ".") && strings.Trim(id, "0123456789.") == ""):
		// a client name cannot contain ':'; digits with dots are taken for IPv4, but digits
		// alone stay a name, as a DoH client ID can be one (/dns-query/42)
		ip := net.ParseIP(id)
		if ip == nil {
			return "", fmt.Errorf("invalid IP address '%s'", id)
		}

		return ip.String(), nil
	}

	if _, err := filepath.Match(id, ""); err != nil {
		return "", fmt.Errorf("invalid client name pattern '%s': %w", id, err)
	}

	return id, nil
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
