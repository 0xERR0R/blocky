package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"time"

	"github.com/0xERR0R/blocky/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("CertProvider", func() {
	var tmpDir string

	BeforeEach(func() {
		tmpDir = GinkgoT().TempDir()
	})

	// writeCert writes a self-signed cert+key pair to tmpDir and returns the file paths.
	writeCert := func(dir string) (certFile, keyFile string) {
		cert, err := util.TLSGenerateSelfSignedCert([]string{"test"})
		Expect(err).Should(Succeed())

		certFile = filepath.Join(dir, "cert.pem")
		keyFile = filepath.Join(dir, "key.pem")

		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})

		keyBytes, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
		Expect(err).Should(Succeed())

		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})

		Expect(os.WriteFile(certFile, certPEM, 0o644)).Should(Succeed())
		Expect(os.WriteFile(keyFile, keyPEM, 0o600)).Should(Succeed())

		return certFile, keyFile
	}

	When("cert files exist", func() {
		It("should load certificate on creation", func(ctx context.Context) {
			certFile, keyFile := writeCert(tmpDir)

			provider, err := NewCertProviderWithInterval(ctx, certFile, keyFile, 500*time.Millisecond)
			Expect(err).Should(Succeed())

			cert, err := provider.GetCertificate(nil)
			Expect(err).Should(Succeed())
			Expect(cert).ShouldNot(BeNil())
		})

		It("should return a valid tls.Certificate", func(ctx context.Context) {
			certFile, keyFile := writeCert(tmpDir)

			provider, err := NewCertProviderWithInterval(ctx, certFile, keyFile, 500*time.Millisecond)
			Expect(err).Should(Succeed())

			cert, err := provider.GetCertificate(&tls.ClientHelloInfo{})
			Expect(err).Should(Succeed())
			Expect(cert).ShouldNot(BeNil())
			Expect(cert.Certificate).ShouldNot(BeEmpty())
		})
	})

	When("cert files don't exist", func() {
		It("should return error", func(ctx context.Context) {
			_, err := NewCertProviderWithInterval(ctx, "/nonexistent/cert.pem", "/nonexistent/key.pem", time.Second)
			Expect(err).Should(HaveOccurred())
		})
	})

	When("cert files are updated", func() {
		It("should reload certificate on next poll", func(ctx context.Context) {
			certFile, keyFile := writeCert(tmpDir)

			provider, err := NewCertProviderWithInterval(ctx, certFile, keyFile, 100*time.Millisecond)
			Expect(err).Should(Succeed())

			// Get original cert
			origCert, err := provider.GetCertificate(nil)
			Expect(err).Should(Succeed())
			Expect(origCert).ShouldNot(BeNil())

			origSerial := origCert.Leaf

			// Wait a moment, then write a new cert
			time.Sleep(50 * time.Millisecond)

			newCert, newCertErr := util.TLSGenerateSelfSignedCert([]string{"test2"})
			Expect(newCertErr).Should(Succeed())

			newCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newCert.Certificate[0]})
			newKeyBytes, marshalErr := x509.MarshalPKCS8PrivateKey(newCert.PrivateKey)
			Expect(marshalErr).Should(Succeed())
			newKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: newKeyBytes})

			// Touch the files with a newer mod time
			futureTime := time.Now().Add(2 * time.Second)
			Expect(os.WriteFile(certFile, newCertPEM, 0o644)).Should(Succeed())
			Expect(os.WriteFile(keyFile, newKeyPEM, 0o600)).Should(Succeed())
			Expect(os.Chtimes(certFile, futureTime, futureTime)).Should(Succeed())
			Expect(os.Chtimes(keyFile, futureTime, futureTime)).Should(Succeed())

			// Wait for reload to happen (poll interval is 100ms, give it some time)
			Eventually(func() interface{} {
				c, _ := provider.GetCertificate(nil)
				if c == nil {
					return nil
				}

				return c.Leaf
			}, 2*time.Second, 50*time.Millisecond).ShouldNot(Equal(origSerial))
		})
	})

	When("UpdatePaths is called", func() {
		It("should force reload on next poll", func(ctx context.Context) {
			certFile, keyFile := writeCert(tmpDir)

			provider, err := NewCertProviderWithInterval(ctx, certFile, keyFile, 100*time.Millisecond)
			Expect(err).Should(Succeed())

			origCert, getErr := provider.GetCertificate(nil)
			Expect(getErr).Should(Succeed())
			Expect(origCert).ShouldNot(BeNil())

			// Overwrite with a new cert (same paths) so the content changes.
			// UpdatePaths zeros lastMod, so the poll will see modTime >= zero and reload.
			newCert, genErr := util.TLSGenerateSelfSignedCert([]string{"test-updated"})
			Expect(genErr).Should(Succeed())
			newCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newCert.Certificate[0]})
			newKeyBytes, marshalErr := x509.MarshalPKCS8PrivateKey(newCert.PrivateKey)
			Expect(marshalErr).Should(Succeed())
			newKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: newKeyBytes})

			Expect(os.WriteFile(certFile, newCertPEM, 0o644)).Should(Succeed())
			Expect(os.WriteFile(keyFile, newKeyPEM, 0o600)).Should(Succeed())

			// Calling UpdatePaths with the same paths but zeroed lastMod triggers reload
			provider.UpdatePaths(certFile, keyFile)

			// The provider should pick up the updated cert within poll interval
			Eventually(func() string {
				c, _ := provider.GetCertificate(nil)
				if c == nil || c.Leaf == nil {
					return ""
				}
				if len(c.Leaf.DNSNames) == 0 {
					return ""
				}

				return c.Leaf.DNSNames[0]
			}, 2*time.Second, 50*time.Millisecond).Should(Equal("test-updated"))
		})
	})
})
