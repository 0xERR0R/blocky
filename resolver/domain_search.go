package resolver

import "github.com/miekg/dns"

// searchDomainOrParent returns the entry of m whose key equals domain or is its
// closest parent domain. Label boundaries are walked with dns.NextLabel, so
// escaped dots (`\.`) inside a label are not treated as separators. Keys and
// domain must use the same canonical form (case, trailing dot).
func searchDomainOrParent[T any](m map[string]T, domain string) (match string, value T, found bool) {
	if domain == "" || len(m) == 0 {
		return "", value, false
	}

	for offset, end := 0, false; !end; offset, end = dns.NextLabel(domain, offset) {
		match = domain[offset:]
		if value, found = m[match]; found {
			return match, value, true
		}
	}

	return "", value, false
}
