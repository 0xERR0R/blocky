package configstore

import (
	"fmt"
	"net"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/miekg/dns"
)

// BuildBlockingConfig replaces the dynamic sections of base with DB state.
// YAML-only fields (e.g. Loading) are preserved.
func (s *ConfigStore) BuildBlockingConfig(base config.Blocking) (config.Blocking, error) {
	groups, err := s.ListClientGroups()
	if err != nil {
		return base, fmt.Errorf("load client groups: %w", err)
	}

	sources, err := s.ListBlocklistSources("", "")
	if err != nil {
		return base, fmt.Errorf("load blocklist sources: %w", err)
	}

	settings, err := s.GetBlockSettings()
	if err != nil {
		return base, fmt.Errorf("load block settings: %w", err)
	}

	// Client groups: expand each group's clients into individual clientGroupsBlock entries.
	// blocky expects keys to be client identifiers (IP, CIDR, "default"), not group names.
	base.ClientGroupsBlock = make(map[string][]string)
	for _, g := range groups {
		if g.Name == "default" {
			base.ClientGroupsBlock["default"] = g.Groups
			continue
		}
		for _, client := range g.Clients {
			base.ClientGroupsBlock[client] = g.Groups
		}
	}

	// Deny/allowlists from sources
	base.Denylists = make(map[string][]config.BytesSource)
	base.Allowlists = make(map[string][]config.BytesSource)

	for _, src := range sources {
		if !src.IsEnabled() {
			continue
		}

		bs := dbSourceToBytes(src)

		switch src.ListType {
		case "deny":
			base.Denylists[src.GroupName] = append(base.Denylists[src.GroupName], bs)
		case "allow":
			base.Allowlists[src.GroupName] = append(base.Allowlists[src.GroupName], bs)
		}
	}

	// Block settings
	base.BlockType = settings.BlockType

	ttl, _ := time.ParseDuration(settings.BlockTTL) // validated on write
	base.BlockTTL = config.Duration(ttl)

	return base, nil
}

// BuildCustomDNSConfig replaces the Mapping in base with DB state.
func (s *ConfigStore) BuildCustomDNSConfig(base config.CustomDNS) (config.CustomDNS, error) {
	entries, err := s.ListCustomDNSEntries()
	if err != nil {
		return base, fmt.Errorf("load custom DNS entries: %w", err)
	}

	mapping := make(config.CustomDNSMapping)

	for _, e := range entries {
		if !e.IsEnabled() {
			continue
		}

		rr, err := entryToRR(e)
		if err != nil {
			return base, fmt.Errorf("convert DNS entry %d: %w", e.ID, err)
		}

		fqdn := dns.Fqdn(e.Domain)
		mapping[fqdn] = append(mapping[fqdn], rr)
	}

	base.Mapping = mapping

	return base, nil
}

func dbSourceToBytes(src BlocklistSource) config.BytesSource {
	switch src.SourceType {
	case "http":
		return config.BytesSource{Type: config.BytesSourceTypeHttp, From: src.Source}
	case "file":
		return config.BytesSource{Type: config.BytesSourceTypeFile, From: src.Source}
	case "text":
		return config.BytesSource{Type: config.BytesSourceTypeText, From: src.Source}
	default:
		return config.BytesSource{Type: config.BytesSourceTypeText, From: src.Source}
	}
}

func entryToRR(e CustomDNSEntry) (dns.RR, error) {
	fqdn := dns.Fqdn(e.Domain)

	switch e.RecordType {
	case "A":
		ip := net.ParseIP(e.Value)
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("invalid A record value %q", e.Value)
		}

		return &dns.A{
			Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: e.TTL},
			A:   ip.To4(),
		}, nil

	case "AAAA":
		ip := net.ParseIP(e.Value)
		if ip == nil || ip.To4() != nil {
			return nil, fmt.Errorf("invalid AAAA record value %q", e.Value)
		}

		return &dns.AAAA{
			Hdr:  dns.RR_Header{Name: fqdn, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: e.TTL},
			AAAA: ip,
		}, nil

	case "CNAME":
		return &dns.CNAME{
			Hdr:    dns.RR_Header{Name: fqdn, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: e.TTL},
			Target: dns.Fqdn(e.Value),
		}, nil

	default:
		return nil, fmt.Errorf("unsupported record type %q", e.RecordType)
	}
}
