package server

import (
	"crypto/tls"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("HTTP/3 helpers", func() {
	Describe("newH3TLSConfig", func() {
		var base *tls.Config

		BeforeEach(func() {
			base = &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{{}},
				NextProtos:   []string{"http/1.1"},
			}
		})

		It("enforces TLS 1.3", func() {
			out := newH3TLSConfig(base)
			Expect(out.MinVersion).To(Equal(uint16(tls.VersionTLS13)))
		})

		It("sets ALPN to h3", func() {
			out := newH3TLSConfig(base)
			Expect(out.NextProtos).To(ContainElement("h3"))
		})

		It("preserves certificates from the base config", func() {
			out := newH3TLSConfig(base)
			Expect(out.Certificates).To(HaveLen(1))
		})

		It("does not mutate the base config", func() {
			_ = newH3TLSConfig(base)
			Expect(base.MinVersion).To(Equal(uint16(tls.VersionTLS12)))
			Expect(base.NextProtos).To(Equal([]string{"http/1.1"}))
		})
	})
})
