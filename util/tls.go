package util

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math"
	"math/big"
	mrand "math/rand"
	"time"
)

const (
	caExpiryYears   = 10
	certExpiryYears = 5
)

//nolint:funlen
func CreateSelfSignedCert() (tls.Certificate, error) {
	// Create CA
	ca := &x509.Certificate{
		//nolint:gosec
		SerialNumber:          big.NewInt(int64(mrand.Intn(math.MaxInt))),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(caExpiryYears, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	caPEM := new(bytes.Buffer)
	if err = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	}); err != nil {
		return tls.Certificate{}, err
	}

	caPrivKeyPEM := new(bytes.Buffer)

	b, err := x509.MarshalECPrivateKey(caPrivKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	if err = pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: b,
	}); err != nil {
		return tls.Certificate{}, err
	}

	// Create certificate
	cert := &x509.Certificate{
		//nolint:gosec
		SerialNumber: big.NewInt(int64(mrand.Intn(math.MaxInt))),
		DNSNames:     []string{"*"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(certExpiryYears, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := new(bytes.Buffer)
	if err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}); err != nil {
		return tls.Certificate{}, err
	}

	certPrivKeyPEM := new(bytes.Buffer)

	b, err = x509.MarshalECPrivateKey(certPrivKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	if err = pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: b,
	}); err != nil {
		return tls.Certificate{}, err
	}

	keyPair, err := tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
	if err != nil {
		return tls.Certificate{}, err
	}

	return keyPair, nil
}
