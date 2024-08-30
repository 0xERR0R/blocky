package util

import (
	"crypto/x509"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("TLS Util", func() {
	Describe("TLSGenerateSelfSignedCert", func() {
		It("returns a good value", func() {
			const domain = "whatever.test.blocky.invalid"

			cert, err := TLSGenerateSelfSignedCert([]string{domain})
			Expect(err).Should(Succeed())

			Expect(cert.Certificate).ShouldNot(BeEmpty())

			By("having the right Leaf", func() {
				fromDER, err := x509.ParseCertificate(cert.Certificate[0])
				Expect(err).Should(Succeed())

				Expect(cert.Leaf).Should(Equal(fromDER))
			})

			By("being valid as self-signed for server TLS on the given domain", func() {
				pool := x509.NewCertPool()
				pool.AddCert(cert.Leaf)

				chain, err := cert.Leaf.Verify(x509.VerifyOptions{
					DNSName:   domain,
					Roots:     pool,
					KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				})
				Expect(err).Should(Succeed())
				Expect(chain).Should(Equal([][]*x509.Certificate{{cert.Leaf}}))
			})

			By("mentioning Blocky", func() {
				Expect(cert.Leaf.Subject.Organization).Should(Equal([]string{"Blocky"}))
			})
		})
	})
})
