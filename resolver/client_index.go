package resolver

import (
	"net"
	"path/filepath"
	"sort"
	"strings"
)

// clientIndex pre-classifies the identifiers of a per-client setting
// (blocking.clientGroupsBlock, customDNS.clientMapping) once at config load so
// per-query resolution avoids re-parsing CIDRs and re-lowercasing identifiers
// on every request (see PERFORMANCE.md, finding #8). It is immutable after
// construction.
type clientIndex[T any] struct {
	// byID maps an exact, already-lowercased identifier (IP literal, FQDN, literal
	// client name or "default") to its value. Used for exact ClientIP, "default"
	// and literal client-name lookups. Identifiers containing glob metacharacters
	// are not kept here; they live in names and are matched via filepath.Match.
	byID map[string]T
	// cidrs holds identifiers that parse as a CIDR, with the network pre-parsed,
	// sorted by identifier.
	cidrs []clientCIDR[T]
	// fqdns holds identifiers classified as FQDN candidates. The index does not
	// resolve them: a resolver that matches clients by FQDN does so itself.
	fqdns []clientFQDN[T]
	// names holds identifiers containing glob metacharacters, matched against
	// client names with filepath.Match, sorted by pattern. This is usually a tiny
	// set, so literal client names avoid scanning it via the byID exact lookup.
	names []clientNameGlob[T]
}

type clientCIDR[T any] struct {
	identifier string
	ipNet      *net.IPNet
	value      T
}

type clientFQDN[T any] struct {
	identifier string
	value      T
}

type clientNameGlob[T any] struct {
	pattern string
	value   T
}

// isClientNameGlob reports whether an identifier contains filepath.Match
// metacharacters. Only such identifiers need a per-name filepath.Match; everything
// else matches a client name exactly and is resolved via the byID map.
func isClientNameGlob(identifier string) bool {
	return strings.ContainsAny(identifier, `*?[\`)
}

// newClientIndex classifies byID, whose keys must already be lowercased single
// identifiers. It takes ownership of byID.
func newClientIndex[T any](byID map[string]T) clientIndex[T] {
	idx := clientIndex[T]{byID: byID}

	for id, value := range byID {
		// Move glob identifiers out of byID into the names bucket: they are only
		// ever matched against client names via filepath.Match, never by exact
		// lookup, and a glob string is neither a valid CIDR nor a resolvable FQDN.
		// Removing them keeps the exact byID lookup faithful (a client whose name
		// literally equals a glob pattern must not match it as a literal).
		if isClientNameGlob(id) {
			idx.names = append(idx.names, clientNameGlob[T]{pattern: id, value: value})
			delete(byID, id)

			continue
		}

		// Pre-parse CIDR identifiers so per-query matching is a cheap
		// ipNet.Contains instead of a net.ParseCIDR allocation per entry.
		if _, ipNet, err := net.ParseCIDR(id); err == nil {
			idx.cidrs = append(idx.cidrs, clientCIDR[T]{identifier: id, ipNet: ipNet, value: value})
		}

		// A CIDR identifier can also be an FQDN candidate (e.g. "10.0.0.0/8"
		// contains a dot); it is kept in both buckets, as isFQDN classifies it.
		if isFQDN(id) {
			idx.fqdns = append(idx.fqdns, clientFQDN[T]{identifier: id, value: value})
		}
	}

	// Map iteration order is random: sort, so that tie-breaks in mostSpecific
	// pick the same identifier on every start.
	sort.Slice(idx.names, func(i, j int) bool { return idx.names[i].pattern < idx.names[j].pattern })
	sort.Slice(idx.cidrs, func(i, j int) bool { return idx.cidrs[i].identifier < idx.cidrs[j].identifier })
	sort.Slice(idx.fqdns, func(i, j int) bool { return idx.fqdns[i].identifier < idx.fqdns[j].identifier })

	return idx
}

// forEachMatch calls fn with the value of every identifier matching the client:
// per client name its literal identifier, then the matching globs; then the
// exact client IP; then every CIDR containing it. FQDN identifiers are not
// resolved here.
func (idx *clientIndex[T]) forEachMatch(clientNames []string, clientIP net.IP, fn func(T)) {
	// identifiers are already lowercased at config load, so the client name is
	// lowered once here instead of both sides per map entry.
	for _, cName := range clientNames {
		lowerName := strings.ToLower(cName)

		if value, found := idx.byID[lowerName]; found {
			fn(value)
		}

		for _, ng := range idx.names {
			if matched, _ := filepath.Match(ng.pattern, lowerName); matched {
				fn(ng.value)
			}
		}
	}

	if value, found := idx.byID[clientIP.String()]; found {
		fn(value)
	}

	for _, c := range idx.cidrs {
		if c.ipNet.Contains(clientIP) {
			fn(c.value)
		}
	}
}

// mostSpecific returns the value of the single identifier that matches the
// client most specifically: a literal client name, then the exact client IP,
// then a client-name glob, then the CIDR with the longest prefix. Literal names
// are tried in the request's order; globs, and CIDRs of equal length, in
// identifier order. FQDN identifiers match client names literally and are not
// resolved to addresses.
func (idx *clientIndex[T]) mostSpecific(clientNames []string, clientIP net.IP) (value T, found bool) {
	for _, cName := range clientNames {
		if value, found := idx.byID[strings.ToLower(cName)]; found {
			return value, true
		}
	}

	if clientIP != nil {
		if value, found := idx.byID[clientIP.String()]; found {
			return value, true
		}
	}

	for _, ng := range idx.names {
		for _, cName := range clientNames {
			if matched, _ := filepath.Match(ng.pattern, strings.ToLower(cName)); matched {
				return ng.value, true
			}
		}
	}

	bestOnes := -1

	for _, c := range idx.cidrs {
		if !c.ipNet.Contains(clientIP) {
			continue
		}

		if ones, _ := c.ipNet.Mask.Size(); ones > bestOnes {
			value, found, bestOnes = c.value, true, ones
		}
	}

	return value, found
}
