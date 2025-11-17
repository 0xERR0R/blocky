package e2e

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// DNSSECTestData holds generated DNSSEC test data for e2e tests
type DNSSECTestData struct {
	ARecord    *dns.A
	RRSIG      *dns.RRSIG
	DNSKEY     *dns.DNSKEY
	PrivateKey *ecdsa.PrivateKey
}

// DNSSECChainData holds a complete DNSSEC chain with parent and child zones
type DNSSECChainData struct {
	// Parent zone (e.g., "example.")
	ParentZone       string
	ParentDNSKEY     *dns.DNSKEY
	ParentPrivateKey *ecdsa.PrivateKey

	// Child zone (e.g., "child.example.")
	ChildZone       string
	ChildDNSKEY     *dns.DNSKEY
	ChildPrivateKey *ecdsa.PrivateKey

	// DS record linking child to parent
	DS *dns.DS

	// DS RRSIG (parent signs the DS record)
	DSRRSIG *dns.RRSIG

	// Child's A record and signature
	ARecord *dns.A
	ARRRSIG *dns.RRSIG

	// DNSKEY RRSIGs (self-signed per RFC 4035 §5.2)
	ChildDNSKEYRRSIG  *dns.RRSIG
	ParentDNSKEYRRSIG *dns.RRSIG
}

// GenerateValidDNSSEC generates a valid DNSSEC-signed A record with matching DNSKEY
// This creates cryptographically correct DNSSEC data for testing validation
//
//nolint:mnd // Test helper function with DNS TTL and key size constants
func GenerateValidDNSSEC(zone, hostname, ipAddr string) (*DNSSECTestData, error) {
	// Create DNSKEY with ECDSA P-256 (fast and modern)
	key := new(dns.DNSKEY)
	key.Hdr = dns.RR_Header{
		Name:   zone,
		Rrtype: dns.TypeDNSKEY,
		Class:  dns.ClassINET,
		Ttl:    3600,
	}
	key.Flags = 257 // Key Signing Key (KSK) with SEP flag for use as trust anchor
	key.Protocol = 3
	key.Algorithm = dns.ECDSAP256SHA256

	// Generate ECDSA keypair (256 bits for P-256)
	privkeyIface, err := key.Generate(256)
	if err != nil {
		return nil, fmt.Errorf("failed to generate DNSKEY: %w", err)
	}

	privkey, ok := privkeyIface.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("generated key is not *ecdsa.PrivateKey")
	}

	// Create A record to sign
	aRecord := &dns.A{
		Hdr: dns.RR_Header{
			Name:   hostname,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.ParseIP(ipAddr),
	}

	// Create RRSIG for the A record
	sig := new(dns.RRSIG)
	sig.Hdr = dns.RR_Header{
		Name:   hostname,
		Rrtype: dns.TypeRRSIG,
		Class:  dns.ClassINET,
		Ttl:    300,
	}
	sig.TypeCovered = dns.TypeA
	sig.Algorithm = dns.ECDSAP256SHA256
	sig.Labels = uint8(dns.CountLabel(aRecord.Hdr.Name))
	sig.OrigTtl = aRecord.Hdr.Ttl
	sig.Expiration = uint32(time.Now().Add(30 * 24 * time.Hour).Unix())
	sig.Inception = uint32(time.Now().Add(-1 * time.Hour).Unix())
	sig.KeyTag = key.KeyTag()
	sig.SignerName = key.Hdr.Name

	// Sign the A record with the private key
	if err := sig.Sign(privkey, []dns.RR{aRecord}); err != nil {
		return nil, fmt.Errorf("failed to sign A record: %w", err)
	}

	return &DNSSECTestData{
		ARecord:    aRecord,
		RRSIG:      sig,
		DNSKEY:     key,
		PrivateKey: privkey,
	}, nil
}

// GenerateMismatchedDNSSEC generates DNSSEC data where RRSIG and DNSKEY don't match
// The A record is signed with keyA, but a different keyB is returned for DNSKEY queries
//
//nolint:mnd // Test helper function with DNS TTL and key size constants
func GenerateMismatchedDNSSEC(zone, hostname, ipAddr string) (*DNSSECTestData, *dns.DNSKEY, error) {
	// Generate the first key and sign with it
	validData, err := GenerateValidDNSSEC(zone, hostname, ipAddr)
	if err != nil {
		return nil, nil, err
	}

	// Generate a second, different DNSKEY
	wrongKey := new(dns.DNSKEY)
	wrongKey.Hdr = dns.RR_Header{
		Name:   zone,
		Rrtype: dns.TypeDNSKEY,
		Class:  dns.ClassINET,
		Ttl:    3600,
	}
	wrongKey.Flags = 257
	wrongKey.Protocol = 3
	wrongKey.Algorithm = dns.ECDSAP256SHA256

	// Generate different keypair
	_, err = wrongKey.Generate(256)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate wrong DNSKEY: %w", err)
	}

	// Return the valid data (signed with keyA) and the wrong key (keyB)
	return validData, wrongKey, nil
}

// GenerateDNSSECChain generates a complete DNSSEC chain with parent and child zones
// This creates a parent zone, child zone, DS record, and all necessary signatures
//
//nolint:funlen,mnd // Test helper function with multiple DNSSEC operations
func GenerateDNSSECChain(parentZone, childZone, hostname, ipAddr string) (*DNSSECChainData, error) {
	chain := &DNSSECChainData{
		ParentZone: parentZone,
		ChildZone:  childZone,
	}

	// Generate parent DNSKEY (KSK)
	parentKey := new(dns.DNSKEY)
	parentKey.Hdr = dns.RR_Header{
		Name:   parentZone,
		Rrtype: dns.TypeDNSKEY,
		Class:  dns.ClassINET,
		Ttl:    3600,
	}
	parentKey.Flags = 257 // KSK with SEP flag
	parentKey.Protocol = 3
	parentKey.Algorithm = dns.ECDSAP256SHA256

	parentPrivkeyIface, err := parentKey.Generate(256)
	if err != nil {
		return nil, fmt.Errorf("failed to generate parent DNSKEY: %w", err)
	}

	parentPrivkey, ok := parentPrivkeyIface.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("parent key is not *ecdsa.PrivateKey")
	}

	chain.ParentDNSKEY = parentKey
	chain.ParentPrivateKey = parentPrivkey

	// Generate child DNSKEY (KSK)
	childKey := new(dns.DNSKEY)
	childKey.Hdr = dns.RR_Header{
		Name:   childZone,
		Rrtype: dns.TypeDNSKEY,
		Class:  dns.ClassINET,
		Ttl:    3600,
	}
	childKey.Flags = 257 // KSK with SEP flag
	childKey.Protocol = 3
	childKey.Algorithm = dns.ECDSAP256SHA256

	childPrivkeyIface, err := childKey.Generate(256)
	if err != nil {
		return nil, fmt.Errorf("failed to generate child DNSKEY: %w", err)
	}

	childPrivkey, ok := childPrivkeyIface.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("child key is not *ecdsa.PrivateKey")
	}

	chain.ChildDNSKEY = childKey
	chain.ChildPrivateKey = childPrivkey

	// Generate DS record for child zone (signed by parent)
	// DS = hash(DNSKEY)
	chain.DS = childKey.ToDS(dns.SHA256)

	// Create RRSIG for DS record (parent signs the DS)
	dsRRSIG := new(dns.RRSIG)
	dsRRSIG.Hdr = dns.RR_Header{
		Name:   childZone,
		Rrtype: dns.TypeRRSIG,
		Class:  dns.ClassINET,
		Ttl:    3600,
	}
	dsRRSIG.TypeCovered = dns.TypeDS
	dsRRSIG.Algorithm = dns.ECDSAP256SHA256
	dsRRSIG.Labels = uint8(dns.CountLabel(chain.DS.Hdr.Name))
	dsRRSIG.OrigTtl = chain.DS.Hdr.Ttl
	dsRRSIG.Expiration = uint32(time.Now().Add(30 * 24 * time.Hour).Unix())
	dsRRSIG.Inception = uint32(time.Now().Add(-1 * time.Hour).Unix())
	dsRRSIG.KeyTag = parentKey.KeyTag()
	dsRRSIG.SignerName = parentZone

	// Parent signs the DS record
	if err := dsRRSIG.Sign(parentPrivkey, []dns.RR{chain.DS}); err != nil {
		return nil, fmt.Errorf("failed to sign DS record: %w", err)
	}

	chain.DSRRSIG = dsRRSIG

	// Create A record in child zone
	aRecord := &dns.A{
		Hdr: dns.RR_Header{
			Name:   hostname,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.ParseIP(ipAddr),
	}
	chain.ARecord = aRecord

	// Create RRSIG for A record (child signs its own A record)
	aRRSIG := new(dns.RRSIG)
	aRRSIG.Hdr = dns.RR_Header{
		Name:   hostname,
		Rrtype: dns.TypeRRSIG,
		Class:  dns.ClassINET,
		Ttl:    300,
	}
	aRRSIG.TypeCovered = dns.TypeA
	aRRSIG.Algorithm = dns.ECDSAP256SHA256
	aRRSIG.Labels = uint8(dns.CountLabel(aRecord.Hdr.Name))
	aRRSIG.OrigTtl = aRecord.Hdr.Ttl
	aRRSIG.Expiration = uint32(time.Now().Add(30 * 24 * time.Hour).Unix())
	aRRSIG.Inception = uint32(time.Now().Add(-1 * time.Hour).Unix())
	aRRSIG.KeyTag = childKey.KeyTag()
	aRRSIG.SignerName = childZone

	// Child signs the A record
	if err := aRRSIG.Sign(childPrivkey, []dns.RR{aRecord}); err != nil {
		return nil, fmt.Errorf("failed to sign A record: %w", err)
	}

	chain.ARRRSIG = aRRSIG

	// Generate RRSIG for child DNSKEY RRset (self-signed per RFC 4035 §5.2)
	childDNSKEYRRSIG := new(dns.RRSIG)
	childDNSKEYRRSIG.Hdr = dns.RR_Header{
		Name:   childZone,
		Rrtype: dns.TypeRRSIG,
		Class:  dns.ClassINET,
		Ttl:    3600,
	}
	childDNSKEYRRSIG.TypeCovered = dns.TypeDNSKEY
	childDNSKEYRRSIG.Algorithm = dns.ECDSAP256SHA256
	childDNSKEYRRSIG.Labels = uint8(dns.CountLabel(childKey.Hdr.Name))
	childDNSKEYRRSIG.OrigTtl = childKey.Hdr.Ttl
	childDNSKEYRRSIG.Expiration = uint32(time.Now().Add(30 * 24 * time.Hour).Unix())
	childDNSKEYRRSIG.Inception = uint32(time.Now().Add(-1 * time.Hour).Unix())
	childDNSKEYRRSIG.KeyTag = childKey.KeyTag()
	childDNSKEYRRSIG.SignerName = childZone

	// Child signs its own DNSKEY (self-signed)
	if err := childDNSKEYRRSIG.Sign(childPrivkey, []dns.RR{childKey}); err != nil {
		return nil, fmt.Errorf("failed to sign child DNSKEY: %w", err)
	}

	chain.ChildDNSKEYRRSIG = childDNSKEYRRSIG

	// Generate RRSIG for parent DNSKEY RRset (self-signed per RFC 4035 §5.2)
	parentDNSKEYRRSIG := new(dns.RRSIG)
	parentDNSKEYRRSIG.Hdr = dns.RR_Header{
		Name:   parentZone,
		Rrtype: dns.TypeRRSIG,
		Class:  dns.ClassINET,
		Ttl:    3600,
	}
	parentDNSKEYRRSIG.TypeCovered = dns.TypeDNSKEY
	parentDNSKEYRRSIG.Algorithm = dns.ECDSAP256SHA256
	parentDNSKEYRRSIG.Labels = uint8(dns.CountLabel(parentKey.Hdr.Name))
	parentDNSKEYRRSIG.OrigTtl = parentKey.Hdr.Ttl
	parentDNSKEYRRSIG.Expiration = uint32(time.Now().Add(30 * 24 * time.Hour).Unix())
	parentDNSKEYRRSIG.Inception = uint32(time.Now().Add(-1 * time.Hour).Unix())
	parentDNSKEYRRSIG.KeyTag = parentKey.KeyTag()
	parentDNSKEYRRSIG.SignerName = parentZone

	// Parent signs its own DNSKEY (self-signed)
	if err := parentDNSKEYRRSIG.Sign(parentPrivkey, []dns.RR{parentKey}); err != nil {
		return nil, fmt.Errorf("failed to sign parent DNSKEY: %w", err)
	}

	chain.ParentDNSKEYRRSIG = parentDNSKEYRRSIG

	return chain, nil
}

// FormatRecordForMokka formats a DNS RR for use in dns-mokka configuration
// Returns the format: "TYPE rdata TTL"
// Example: "A 192.0.2.1 300"
func FormatRecordForMokka(rr dns.RR) string {
	hdr := rr.Header()

	// Type-specific formatting for mokka
	switch r := rr.(type) {
	case *dns.A:
		return fmt.Sprintf("A %s %d", r.A.String(), hdr.Ttl)
	case *dns.RRSIG:
		// RRSIG format for mokka: "RRSIG typecovered alg labels origttl exp inc keytag signer signature TTL"
		return fmt.Sprintf("RRSIG %s %d %d %d %d %d %d %s %s %d",
			dns.TypeToString[r.TypeCovered],
			r.Algorithm,
			r.Labels,
			r.OrigTtl,
			r.Expiration,
			r.Inception,
			r.KeyTag,
			r.SignerName,
			r.Signature,
			hdr.Ttl,
		)
	case *dns.DNSKEY:
		// DNSKEY format for mokka: "DNSKEY flags protocol alg publickey TTL"
		return fmt.Sprintf("DNSKEY %d %d %d %s %d",
			r.Flags,
			r.Protocol,
			r.Algorithm,
			r.PublicKey,
			hdr.Ttl,
		)
	case *dns.DS:
		// DS format for mokka: "DS keytag alg digesttype digest TTL"
		return fmt.Sprintf("DS %d %d %d %s %d",
			r.KeyTag,
			r.Algorithm,
			r.DigestType,
			r.Digest,
			hdr.Ttl,
		)
	default:
		return rr.String()
	}
}
