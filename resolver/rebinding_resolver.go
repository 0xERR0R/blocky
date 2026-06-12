package resolver

import (
	"context"
	"net"
	"strings"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
)

// RebindingProtectionResolver drops answers that contain private, loopback, link-local
// or unspecified IPs for non-allowlisted domains (DNS rebinding protection).
//
// It must sit directly above the upstream tree in the chain: answers from conditional
// upstreams, custom DNS, the hosts file and special-use domain handling are exempt
// because they never pass through this resolver.
type RebindingProtectionResolver struct {
	configurable[*config.RebindingProtection]
	NextResolver
	typed

	allowedDomains map[string]struct{}
}

// NewRebindingProtectionResolver returns a new resolver instance
func NewRebindingProtectionResolver(cfg config.RebindingProtection) *RebindingProtectionResolver {
	allowed := make(map[string]struct{}, len(cfg.AllowedDomains))
	for _, domain := range cfg.AllowedDomains {
		// normalize: lowercase, no trailing dot
		allowed[util.ExtractDomainOnly(strings.TrimSpace(domain))] = struct{}{}
	}

	return &RebindingProtectionResolver{
		configurable:   withConfig(&cfg),
		typed:          withType("rebinding_protection"),
		allowedDomains: allowed,
	}
}

// Resolve inspects the next resolver's answer and replaces it with an empty FILTERED
// response if it contains a non-public IP.
func (r *RebindingProtectionResolver) Resolve(ctx context.Context, request *model.Request) (*model.Response, error) {
	if !r.IsEnabled() {
		return r.next.Resolve(ctx, request)
	}

	response, err := r.next.Resolve(ctx, request)
	if err != nil {
		return nil, err
	}

	if response == nil || response.Res == nil || len(response.Res.Answer) == 0 {
		return response, nil
	}

	// scan first: most answers are public, so the common path skips question-name
	// extraction and the allowlist walk entirely; the outcome is order-independent
	ip := findBlockedIP(response.Res.Answer)
	if ip == nil {
		return response, nil
	}

	domain := util.ExtractDomain(request.Req.Question[0])
	if r.isAllowed(domain) {
		return response, nil
	}

	_, logger := r.log(ctx)
	logger.WithField(logFieldDomain, util.Obfuscate(domain)).
		Debugf("dropped answer with non-public IP %s", ip)

	// fixed reason: it becomes a Prometheus label via MetricsResolver, and the IP is
	// attacker-chosen — embedding it would allow unbounded cardinality growth
	return model.NewResponseWithRcode(request, dns.RcodeSuccess, model.ResponseTypeFILTERED,
		"FILTERED (rebinding protection)"), nil
}

// isAllowed reports whether the queried domain matches an allowlist entry exactly
// or is a subdomain of one.
func (r *RebindingProtectionResolver) isAllowed(domain string) bool {
	for len(domain) > 0 {
		if _, found := r.allowedDomains[domain]; found {
			return true
		}

		i := strings.Index(domain, ".")
		if i < 0 {
			break
		}

		domain = domain[i+1:]
	}

	return false
}

// findBlockedIP returns the first non-public IP found in the A/AAAA records or HTTPS/SVCB ip hints of the
// given answer section, or nil if there is none.
func findBlockedIP(answers []dns.RR) net.IP {
	for _, rr := range answers {
		switch v := rr.(type) {
		case *dns.A:
			if isBlockedIP(v.A) {
				return v.A
			}
		case *dns.AAAA:
			if isBlockedIP(v.AAAA) {
				return v.AAAA
			}
		case *dns.HTTPS:
			if ip := findBlockedHintIP(v.Value); ip != nil {
				return ip
			}
		case *dns.SVCB:
			if ip := findBlockedHintIP(v.Value); ip != nil {
				return ip
			}
		}
	}

	return nil
}

// findBlockedHintIP returns the first non-public IP in the ipv4hint/ipv6hint
// SvcParams of an HTTPS/SVCB record, or nil if there is none.
func findBlockedHintIP(values []dns.SVCBKeyValue) net.IP {
	for _, kv := range values {
		switch hint := kv.(type) {
		case *dns.SVCBIPv4Hint:
			for _, ip := range hint.Hint {
				if isBlockedIP(ip) {
					return ip
				}
			}
		case *dns.SVCBIPv6Hint:
			for _, ip := range hint.Hint {
				if isBlockedIP(ip) {
					return ip
				}
			}
		}
	}

	return nil
}

// isBlockedIP reports whether ip belongs to one of the fixed non-public ranges:
// RFC1918/ULA, loopback, link-local or unspecified. IPv4-mapped IPv6 addresses are
// evaluated as their 4-byte form by these predicates. A nil IP (address-less record)
// returns false by design.
func isBlockedIP(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
}
