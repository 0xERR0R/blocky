package dnssec

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// rootAnchor represents a root KSK trust anchor with metadata
type rootAnchor struct {
	name   string
	keytag uint16
	ds     string // DNSKEY in zone file format
}

const (
	// Root KSK key tags from IANA
	ksk2017Tag = 20326 // KSK-2017
	ksk2024Tag = 38696 // KSK-2024
)

// getDefaultRootTrustAnchors returns the default root KSK trust anchors from IANA
// Source: https://data.iana.org/root-anchors/root-anchors.xml
// Last Updated: 2025-10-29
//
// Includes two root KSKs:
// - KSK-2017 (Key Tag 20326): Active since February 2017
// - KSK-2024 (Key Tag 38696): Active since July 2024
func getDefaultRootTrustAnchors() []string {
	anchors := []rootAnchor{
		{
			name:   "KSK-2017",
			keytag: ksk2017Tag,
			ds: ". 172800 IN DNSKEY 257 3 8 " +
				"AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8k" +
				"vArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr" +
				"+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6" +
				"UwNR1AkUTV74bU=",
		},
		{
			name:   "KSK-2024",
			keytag: ksk2024Tag,
			ds: ". 172800 IN DNSKEY 257 3 8 " +
				"AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeH" +
				"bGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CP" +
				"qpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GN" +
				"UUeayffKC73PYc=",
		},
	}

	result := make([]string, len(anchors))
	for i, anchor := range anchors {
		result[i] = anchor.ds
	}

	return result
}

// TrustAnchor represents a DNSSEC trust anchor (DNSKEY record)
type TrustAnchor struct {
	Key *dns.DNSKEY
}

// TrustAnchorStore manages DNSSEC trust anchors
type TrustAnchorStore struct {
	anchors map[string][]*TrustAnchor // keyed by domain name
	// configured holds the domains for which the operator explicitly supplied a trust
	// anchor. It deliberately excludes the implicit default root anchor: an operator
	// anchor is an assertion "this specific zone is signed" (so unsigned answers for it
	// can be rejected), whereas the default root anchor covers the whole namespace -
	// most of which is legitimately unsigned - and must not trigger fail-closed behavior.
	configured map[string]struct{}
}

// NewTrustAnchorStore creates a new trust anchor store with the given trust anchors.
//
// If customAnchors is empty, the default root KSK trust anchors from IANA are used.
// Custom anchors should be DNSKEY records in zone file format, with the SEP (KSK) flag set.
//
// Example anchor format:
//
//	". 172800 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvk..."
//
// Parameters:
//   - customAnchors: List of DNSKEY record strings to use as trust anchors (optional)
//
// Returns a configured trust anchor store or an error if any anchor is invalid.
func NewTrustAnchorStore(customAnchors []string) (*TrustAnchorStore, error) {
	store := &TrustAnchorStore{
		anchors:    make(map[string][]*TrustAnchor),
		configured: make(map[string]struct{}),
	}

	// Load custom trust anchors if provided, otherwise use defaults. Only operator-supplied
	// anchors are recorded as "configured"; the implicit default root anchor is not, so it
	// does not make every name appear to live under a trust anchor (see HasConfiguredTrustAnchor).
	operatorConfigured := len(customAnchors) > 0

	anchors := customAnchors
	if len(anchors) == 0 {
		anchors = getDefaultRootTrustAnchors()
	}

	for _, anchor := range anchors {
		if err := store.addTrustAnchor(anchor, operatorConfigured); err != nil {
			return nil, fmt.Errorf("failed to load trust anchor: %w", err)
		}
	}

	return store, nil
}

// AddTrustAnchor adds an operator-configured trust anchor from a DNSKEY record string.
func (s *TrustAnchorStore) AddTrustAnchor(anchorStr string) error {
	return s.addTrustAnchor(anchorStr, true)
}

// addTrustAnchor adds a trust anchor; configured marks it as operator-supplied (as opposed
// to the implicit default root anchor) for HasConfiguredTrustAnchor.
func (s *TrustAnchorStore) addTrustAnchor(anchorStr string, configured bool) error {
	// Parse the DNSKEY record
	rr, err := dns.NewRR(anchorStr)
	if err != nil {
		return fmt.Errorf("failed to parse trust anchor: %w", err)
	}

	dnskey, ok := rr.(*dns.DNSKEY)
	if !ok {
		return errors.New("trust anchor is not a DNSKEY record")
	}

	// Validate that it's a KSK (Secure Entry Point)
	if dnskey.Flags&dns.SEP == 0 {
		return errors.New("trust anchor is not a KSK (SEP flag not set)")
	}

	// Normalize domain name
	domain := strings.ToLower(dnskey.Header().Name)

	// Add to store
	anchor := &TrustAnchor{
		Key: dnskey,
	}

	s.anchors[domain] = append(s.anchors[domain], anchor)
	if configured {
		if s.configured == nil {
			s.configured = make(map[string]struct{})
		}
		s.configured[domain] = struct{}{}
	}

	return nil
}

// HasConfiguredTrustAnchor reports whether the operator explicitly configured a trust
// anchor for the domain. Unlike HasTrustAnchor it excludes the implicit default root
// anchor, so it answers "did the operator assert that this specific zone is signed?".
func (s *TrustAnchorStore) HasConfiguredTrustAnchor(domain string) bool {
	domain = strings.ToLower(dns.Fqdn(domain))
	_, ok := s.configured[domain]

	return ok
}

// GetTrustAnchors returns trust anchors for a domain
func (s *TrustAnchorStore) GetTrustAnchors(domain string) []*TrustAnchor {
	domain = strings.ToLower(dns.Fqdn(domain))

	return s.anchors[domain]
}

// HasTrustAnchor returns true if the store has a trust anchor for the domain
func (s *TrustAnchorStore) HasTrustAnchor(domain string) bool {
	domain = strings.ToLower(dns.Fqdn(domain))

	return len(s.anchors[domain]) > 0
}

// GetRootTrustAnchors returns trust anchors for the root zone
func (s *TrustAnchorStore) GetRootTrustAnchors() []*TrustAnchor {
	return s.GetTrustAnchors(".")
}
