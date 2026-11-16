package dnssec

// This file verifies RSA/SHA-256 and RSA/SHA-512 signatures made by DNSKEYs whose public
// exponent Go's crypto/rsa cannot load. RFC 3110 §2 limits the exponent to 4096 bits, but Go
// rejects any exponent >= 2^31-1, so a validly signed zone using e.g. 2^32+1 fails to validate
// with miekg/dns and is otherwise degraded to Insecure or Bogus (issue #2364). The exponent is
// public, so the signature is verified here with math/big instead.

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash"
	"math/big"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

const (
	rsaExponentMaxBytes = 512 // RFC 3110 §2: the exponent is limited to 4096 bits
	rsaModulusMinBytes  = 64  // RFC 3110 §3: the modulus is at least 512 bits
	rsaModulusMaxBytes  = 512 // RFC 3110 §3: the modulus is at most 4096 bits

	extendedExpHeaderLen = 3 // RFC 3110 §2: a 0x00 length byte followed by a 2-octet length
	minRSAExponent       = 3 // an RSA public exponent must be odd and greater than 2

	maxDomainNameWireLen = 255 // RFC 1035 §2.3.4: a domain name is at most 255 octets

	pkcs1BlockType   = 0x01
	pkcs1ZeroByte    = 0x00
	pkcs1PSByte      = 0xff
	pkcs1MinPSBytes  = 8
	pkcs1OverheadLen = 3 // the 0x00 0x01 ... 0x00 framing of EMSA-PKCS1-v1_5

	rsaSHA256DigestInfoPrefix = "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"
	rsaSHA512DigestInfoPrefix = "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40"
)

// parseRSAKey parses the RFC 3110 public key of an RSA DNSKEY into its exponent and modulus.
// It accepts exponents up to 4096 bits, which Go's crypto/rsa cannot load, so signatures made by
// such keys can still be verified with math/big. ok is false when key is not RSA, is malformed,
// or exceeds the RFC 3110 exponent/modulus limits.
func parseRSAKey(key *dns.DNSKEY) (e, n *big.Int, ok bool) {
	switch key.Algorithm {
	case dns.RSASHA1, dns.RSASHA1NSEC3SHA1, dns.RSASHA256, dns.RSASHA512:
	default:
		return nil, nil, false
	}

	pub, err := base64.StdEncoding.DecodeString(key.PublicKey)
	if err != nil || len(pub) == 0 {
		return nil, nil, false
	}

	expLen, offset := int(pub[0]), 1
	if expLen == 0 {
		if len(pub) < extendedExpHeaderLen {
			return nil, nil, false
		}

		expLen = int(pub[1])<<bitsPerByte | int(pub[2])
		offset = extendedExpHeaderLen
	}

	// RFC 3110 §2: the exponent is at most 4096 bits and leading zero octets are prohibited.
	if expLen == 0 || expLen > rsaExponentMaxBytes || len(pub) < offset+expLen || pub[offset] == 0 {
		return nil, nil, false
	}

	e = new(big.Int).SetBytes(pub[offset : offset+expLen])

	// An RSA public exponent must be odd and greater than 2 (mirroring crypto/rsa's checkPub).
	if e.Bit(0) == 0 || e.Cmp(big.NewInt(minRSAExponent)) < 0 {
		return nil, nil, false
	}

	mod := pub[offset+expLen:]
	// RFC 3110 §2/§3: the modulus is 512-4096 bits and leading zero octets are prohibited.
	if len(mod) < rsaModulusMinBytes || len(mod) > rsaModulusMaxBytes || mod[0] == 0 {
		return nil, nil, false
	}

	n = new(big.Int).SetBytes(mod)

	return e, n, true
}

// rsaKeyNeedsBigMath reports whether key is an RSA/SHA-256 or RSA/SHA-512 DNSKEY whose exponent
// exceeds Go's crypto/rsa limit (2^31-1) but is within RFC 3110's 4096-bit limit, so its
// signatures must be verified with math/big. RSA/SHA-1 is deliberately excluded: it is a
// deprecated algorithm and is left to the existing unsupported-exponent handling.
func rsaKeyNeedsBigMath(key *dns.DNSKEY) bool {
	switch key.Algorithm {
	case dns.RSASHA256, dns.RSASHA512:
	default:
		return false
	}

	e, _, ok := parseRSAKey(key)

	return ok && e.BitLen() > 31
}

// verifyRSAWithBigExponent verifies an RRSIG made by an RSA DNSKEY using math/big. It works for
// any in-bounds RSA exponent, including ones Go's crypto/rsa cannot load. It reconstructs the
// signed data per RFC 4035 §5.3.2 and verifies the PKCS#1 v1.5 signature per RFC 3110 §3.
func verifyRSAWithBigExponent(rrset []dns.RR, rrsig *dns.RRSIG, key *dns.DNSKEY) error {
	e, n, ok := parseRSAKey(key)
	if !ok {
		return errRRSIGVerificationFailed
	}

	h, digestInfoPrefix, err := rsaHashForAlgorithm(rrsig.Algorithm)
	if err != nil {
		return err
	}

	signedData, err := buildRRSIGSignedData(rrset, rrsig)
	if err != nil {
		return err
	}

	h.Write(signedData)
	digest := h.Sum(nil)

	sig, err := base64.StdEncoding.DecodeString(rrsig.Signature)
	if err != nil {
		return err
	}

	if !verifyPKCS1v15(n, e, digestInfoPrefix, digest, sig) {
		return errRRSIGVerificationFailed
	}

	return nil
}

// rsaHashForAlgorithm returns the hash and ASN.1 DigestInfo prefix for an RSA signature
// algorithm. RSA/SHA-1 is not handled here: it is a deprecated algorithm whose signatures Go's
// crypto/rsa can verify directly for every exponent it can load.
func rsaHashForAlgorithm(alg uint8) (hash.Hash, []byte, error) {
	switch alg {
	case dns.RSASHA256:
		return sha256.New(), []byte(rsaSHA256DigestInfoPrefix), nil
	case dns.RSASHA512:
		return sha512.New(), []byte(rsaSHA512DigestInfoPrefix), nil
	default:
		return nil, nil, errors.New("unsupported RSA hash algorithm")
	}
}

// buildRRSIGSignedData reconstructs the bytes that were hashed to produce an RRSIG per
// RFC 4035 §5.3.2: the RRSIG RDATA minus the signature, followed by the canonical form of the
// RRset (RFC 4034 §6.2). It mirrors miekg/dns's unexported rawSignatureData and packSigWire so
// signatures can be verified independently of Go's crypto/rsa exponent limit.
func buildRRSIGSignedData(rrset []dns.RR, rrsig *dns.RRSIG) ([]byte, error) {
	rdData, err := packRRSIGRDATA(rrsig)
	if err != nil {
		return nil, err
	}

	rrsetData, err := canonicalRRsetData(rrset, rrsig)
	if err != nil {
		return nil, err
	}

	return append(rdData, rrsetData...), nil
}

// packRRSIGRDATA packs the RRSIG RDATA fields that precede the signature in wire format.
func packRRSIGRDATA(rrsig *dns.RRSIG) ([]byte, error) {
	buf := make([]byte, 0, maxDomainNameWireLen)
	buf = binary.BigEndian.AppendUint16(buf, rrsig.TypeCovered)
	buf = append(buf, rrsig.Algorithm, rrsig.Labels)
	buf = binary.BigEndian.AppendUint32(buf, rrsig.OrigTtl)
	buf = binary.BigEndian.AppendUint32(buf, rrsig.Expiration)
	buf = binary.BigEndian.AppendUint32(buf, rrsig.Inception)
	buf = binary.BigEndian.AppendUint16(buf, rrsig.KeyTag)

	nameBuf := make([]byte, maxDomainNameWireLen)
	n, err := dns.PackDomainName(dns.CanonicalName(rrsig.SignerName), nameBuf, 0, nil, false)
	if err != nil {
		return nil, err
	}

	return append(buf, nameBuf[:n]...), nil
}

// canonicalRRsetData builds the canonical wire form of rrset per RFC 4034 §6.2: TTLs replaced by
// the RRSIG original TTL, wildcard names expanded, domain names lowercased, and records sorted
// and de-duplicated.
func canonicalRRsetData(rrset []dns.RR, rrsig *dns.RRSIG) ([]byte, error) {
	wires := make([][]byte, len(rrset))

	for i, r := range rrset {
		r1 := dns.Copy(r)
		h := r1.Header()
		h.Ttl = rrsig.OrigTtl

		labels := dns.SplitDomainName(h.Name)
		if len(labels) > int(rrsig.Labels) {
			h.Name = "*." + strings.Join(labels[len(labels)-int(rrsig.Labels):], ".") + "."
		}

		h.Name = dns.CanonicalName(h.Name)
		canonicalizeRRDANames(r1)

		wire := make([]byte, dns.Len(r1)+1)
		off, err := dns.PackRR(r1, wire, 0, nil, false)
		if err != nil {
			return nil, err
		}

		wires[i] = wire[:off]
	}

	sort.Slice(wires, func(i, j int) bool { return bytes.Compare(wires[i], wires[j]) < 0 })

	var buf []byte

	for i, wire := range wires {
		if i > 0 && bytes.Equal(wire, wires[i-1]) {
			continue
		}

		buf = append(buf, wire...)
	}

	return buf, nil
}

// canonicalizeRRDANames lowercases the domain names in an RR's RDATA per RFC 4034 §6.2 (3). It
// mirrors the list in miekg/dns's rawSignatureData.
func canonicalizeRRDANames(rr dns.RR) {
	canonicalizeRRDAName(rr)
	canonicalizeRRDANamePairs(rr)
}

// canonicalizeRRDAName lowercases the single domain name in an RR's RDATA.
func canonicalizeRRDAName(rr dns.RR) {
	switch x := rr.(type) {
	case *dns.NS:
		x.Ns = dns.CanonicalName(x.Ns)
	case *dns.MD:
		x.Md = dns.CanonicalName(x.Md)
	case *dns.MF:
		x.Mf = dns.CanonicalName(x.Mf)
	case *dns.CNAME:
		x.Target = dns.CanonicalName(x.Target)
	case *dns.MB:
		x.Mb = dns.CanonicalName(x.Mb)
	case *dns.MG:
		x.Mg = dns.CanonicalName(x.Mg)
	case *dns.MR:
		x.Mr = dns.CanonicalName(x.Mr)
	case *dns.PTR:
		x.Ptr = dns.CanonicalName(x.Ptr)
	case *dns.MX:
		x.Mx = dns.CanonicalName(x.Mx)
	case *dns.AFSDB:
		x.Hostname = dns.CanonicalName(x.Hostname)
	case *dns.RT:
		x.Host = dns.CanonicalName(x.Host)
	case *dns.SIG:
		x.SignerName = dns.CanonicalName(x.SignerName)
	case *dns.NAPTR:
		x.Replacement = dns.CanonicalName(x.Replacement)
	case *dns.KX:
		x.Exchanger = dns.CanonicalName(x.Exchanger)
	case *dns.SRV:
		x.Target = dns.CanonicalName(x.Target)
	case *dns.DNAME:
		x.Target = dns.CanonicalName(x.Target)
	}
}

// canonicalizeRRDANamePairs lowercases the two domain names in an RR's RDATA.
func canonicalizeRRDANamePairs(rr dns.RR) {
	switch x := rr.(type) {
	case *dns.SOA:
		x.Ns = dns.CanonicalName(x.Ns)
		x.Mbox = dns.CanonicalName(x.Mbox)
	case *dns.MINFO:
		x.Rmail = dns.CanonicalName(x.Rmail)
		x.Email = dns.CanonicalName(x.Email)
	case *dns.RP:
		x.Mbox = dns.CanonicalName(x.Mbox)
		x.Txt = dns.CanonicalName(x.Txt)
	case *dns.PX:
		x.Map822 = dns.CanonicalName(x.Map822)
		x.Mapx400 = dns.CanonicalName(x.Mapx400)
	}
}

// verifyPKCS1v15 verifies an EMSA-PKCS1-v1_5 signature per RFC 3447 §8.2.2 with math/big,
// avoiding Go's crypto/rsa exponent limit.
func verifyPKCS1v15(n, e *big.Int, digestInfoPrefix, hashed, sig []byte) bool {
	k := (n.BitLen() + bitsPerByte - 1) / bitsPerByte
	if len(sig) != k {
		return false
	}

	c := new(big.Int).SetBytes(sig)
	if c.Cmp(n) >= 0 {
		return false
	}

	em := new(big.Int).Exp(c, e, n).Bytes()
	em = leftPad(em, k)

	expected := make([]byte, 0, k)
	expected = append(expected, pkcs1ZeroByte, pkcs1BlockType)

	psLen := k - pkcs1OverheadLen - len(digestInfoPrefix) - len(hashed)
	if psLen < pkcs1MinPSBytes {
		return false
	}

	for range psLen {
		expected = append(expected, pkcs1PSByte)
	}

	expected = append(expected, pkcs1ZeroByte)
	expected = append(expected, digestInfoPrefix...)
	expected = append(expected, hashed...)

	return subtle.ConstantTimeCompare(em, expected) == 1
}

// leftPad left-pads b to length with leading zeros, the inverse of big.Int.Bytes.
func leftPad(b []byte, length int) []byte {
	if len(b) >= length {
		return b
	}

	padded := make([]byte, length)
	copy(padded[length-len(b):], b)

	return padded
}
