package dnssec

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"time"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	bigRSAModulusBits = 1024
	bigRSAExponent    = 1<<32 + 1 // 2^32+1, an RFC 3110 exponent Go's crypto/rsa cannot load
)

// generateBigExponentRSAKey builds an RFC 3110 RSA DNSKEY whose public exponent is 2^32+1.
// Go's crypto/rsa refuses such keys, which is exactly the class of key issue #2364 exercises.
// It returns the DNSKEY, its exponent, modulus and private exponent (for signing).
func generateBigExponentRSAKey(name string) (*dns.DNSKEY, *big.Int, *big.Int, *big.Int) {
	e := new(big.Int).SetUint64(bigRSAExponent)
	one := big.NewInt(1)

	for {
		key, err := rsa.GenerateKey(rand.Reader, bigRSAModulusBits)
		Expect(err).Should(Succeed())

		p := key.Primes[0]
		q := key.Primes[1]
		n := new(big.Int).Mul(p, q)
		phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))

		if new(big.Int).GCD(nil, nil, e, phi).Cmp(one) != 0 {
			continue
		}

		d := new(big.Int).ModInverse(e, phi)

		return bigExponentDNSKEY(name, e, n), e, n, d
	}
}

// bigExponentDNSKEY encodes an RSA DNSKEY per RFC 3110 from exponent e and modulus n.
func bigExponentDNSKEY(name string, e, n *big.Int) *dns.DNSKEY {
	exp := e.Bytes()
	pub := append([]byte{byte(len(exp))}, exp...)
	pub = append(pub, n.Bytes()...)

	return &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}
}

// signDNSKEYWithBigExponent signs a DNSKEY RRset with the private exponent d of modulus n using
// math/big (Go's crypto/rsa cannot sign with e = 2^32+1).
func signDNSKEYWithBigExponent(dnskey *dns.DNSKEY, n, d *big.Int) *dns.RRSIG {
	return signRRsetWithBigExponent([]dns.RR{dnskey}, dns.TypeDNSKEY, dnskey, n, d)
}

// signRRsetWithBigExponent signs rrset with the private exponent d of modulus n using math/big.
// It reuses buildRRSIGSignedData so the signed bytes match what verification reconstructs.
func signRRsetWithBigExponent(rrset []dns.RR, rtype uint16, key *dns.DNSKEY, n, d *big.Int) *dns.RRSIG {
	owner := rrset[0].Header().Name

	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: rrset[0].Header().Ttl},
		TypeCovered: rtype,
		Algorithm:   dns.RSASHA256,
		Labels:      uint8(dns.CountLabel(owner)),
		OrigTtl:     rrset[0].Header().Ttl,
		Expiration:  uint32(time.Now().Add(24 * time.Hour).Unix()),
		Inception:   uint32(time.Now().Add(-time.Hour).Unix()),
		KeyTag:      key.KeyTag(),
		SignerName:  dns.Fqdn(key.Hdr.Name),
	}

	signedData, err := buildRRSIGSignedData(rrset, sig)
	Expect(err).Should(Succeed())

	digest := sha256.Sum256(signedData)
	k := (n.BitLen() + 7) / 8
	em := pkcs1v15EncodeSHA256(digest[:], k)

	sig.Signature = base64.StdEncoding.EncodeToString(leftPadBig(new(big.Int).Exp(
		new(big.Int).SetBytes(em), d, n).Bytes(), k))

	return sig
}

// pkcs1v15EncodeSHA256 builds the EMSA-PKCS1-v1_5 encoding of a SHA-256 digest for a k-byte modulus.
func pkcs1v15EncodeSHA256(hashed []byte, k int) []byte {
	const sha256DigestInfoPrefix = "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"

	em := make([]byte, 0, k)
	em = append(em, 0x00, 0x01)
	for range k - 3 - len(sha256DigestInfoPrefix) - len(hashed) {
		em = append(em, 0xff)
	}
	em = append(em, 0x00)
	em = append(em, sha256DigestInfoPrefix...)
	em = append(em, hashed...)

	return em
}

// leftPadBig left-pads b to length with leading zeros, the inverse of big.Int.Bytes.
func leftPadBig(b []byte, length int) []byte {
	if len(b) >= length {
		return b
	}

	padded := make([]byte, length)
	copy(padded[length-len(b):], b)

	return padded
}

var _ = Describe("big-exponent RSA verification", func() {
	Describe("parseRSAKey", func() {
		It("parses an RFC 3110 key whose exponent is 2^32+1", func() {
			key, e, n, _ := generateBigExponentRSAKey("signed.example.")

			gotE, gotN, ok := parseRSAKey(key)
			Expect(ok).Should(BeTrue())
			Expect(gotE.Cmp(e)).Should(BeZero())
			Expect(gotN.Cmp(n)).Should(BeZero())
		})

		It("rejects an exponent longer than RFC 3110's 4096-bit limit", func() {
			key, _, n, _ := generateBigExponentRSAKey("signed.example.")
			overlong := make([]byte, rsaExponentMaxBytes+1)
			overlong[0] = 1
			pub := append(append([]byte{byte(len(overlong))}, overlong...), n.Bytes()...)

			key.PublicKey = base64.StdEncoding.EncodeToString(pub)
			_, _, ok := parseRSAKey(key)
			Expect(ok).Should(BeFalse())
		})
	})

	Describe("verifyRSAWithBigExponent", func() {
		It("verifies a DNSKEY RRset signed by a normal RSA key, matching miekg/dns canonicalization", func() {
			key := &dns.DNSKEY{
				Hdr:       dns.RR_Header{Name: dns.Fqdn("signed.example."), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
				Flags:     257,
				Protocol:  3,
				Algorithm: dns.RSASHA256,
			}
			priv, err := key.Generate(bigRSAModulusBits)
			Expect(err).Should(Succeed())
			rsaPriv := priv.(*rsa.PrivateKey)

			sig := new(dns.RRSIG)
			sig.Hdr = dns.RR_Header{Name: key.Hdr.Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: key.Hdr.Ttl}
			sig.TypeCovered = dns.TypeDNSKEY
			sig.Algorithm = dns.RSASHA256
			sig.Labels = uint8(dns.CountLabel(key.Hdr.Name))
			sig.OrigTtl = key.Hdr.Ttl
			sig.Expiration = uint32(time.Now().Add(24 * time.Hour).Unix())
			sig.Inception = uint32(time.Now().Add(-time.Hour).Unix())
			sig.KeyTag = key.KeyTag()
			sig.SignerName = key.Hdr.Name
			Expect(sig.Sign(rsaPriv, []dns.RR{key})).Should(Succeed())

			Expect(verifyRSAWithBigExponent([]dns.RR{key}, sig, key)).Should(Succeed())
		})

		It("verifies a DNSKEY RRset signed by a key whose exponent is 2^32+1", func() {
			key, _, n, d := generateBigExponentRSAKey("signed.example.")
			sig := signDNSKEYWithBigExponent(key, n, d)

			Expect(verifyRSAWithBigExponent([]dns.RR{key}, sig, key)).Should(Succeed())
		})

		It("rejects a tampered signature", func() {
			key, _, n, d := generateBigExponentRSAKey("signed.example.")
			sig := signDNSKEYWithBigExponent(key, n, d)

			sigBytes, err := base64.StdEncoding.DecodeString(sig.Signature)
			Expect(err).Should(Succeed())
			sigBytes[0] ^= 0xff
			sig.Signature = base64.StdEncoding.EncodeToString(sigBytes)

			Expect(verifyRSAWithBigExponent([]dns.RR{key}, sig, key)).ShouldNot(Succeed())
		})
	})
})
