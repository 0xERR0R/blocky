package util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

const (
	certSerialMaxBits = 128
	certExpiryYears   = 5
)

// TLSGenerateSelfSignedCert returns a new self-signed cert for the given domains.
//
// Being self-signed, no client will trust this certificate.
func TLSGenerateSelfSignedCert(domains []string) (tls.Certificate, error) {
	serialMax := new(big.Int).Lsh(big.NewInt(1), certSerialMaxBits)
	serial, err := rand.Int(rand.Reader, serialMax)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,

		Subject:  pkix.Name{Organization: []string{"Blocky"}},
		DNSNames: domains,

		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(certExpiryYears, 0, 0),

		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("unable to generate private key: %w", err)
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("cert creation from template failed: %w", err)
	}

	// Parse the generated DER back into a useable cert
	// This avoids needing to do it for each TLS handshake (see tls.Certificate.Leaf comment)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generated cert DER could not be parsed: %w", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  privKey,
		Leaf:        cert,
	}

	return tlsCert, nil
}
