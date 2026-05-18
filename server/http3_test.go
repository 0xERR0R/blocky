package server

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/util"
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
	Describe("newHTTP3Server", func() {
		It("returns a server named http3", func() {
			s := newHTTP3Server(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}), &tls.Config{MinVersion: tls.VersionTLS13})

			Expect(s).ShouldNot(BeNil())
			Expect(s.String()).To(Equal("http3"))
			Expect(s.inner.Handler).ShouldNot(BeNil())
			Expect(s.inner.TLSConfig).ShouldNot(BeNil())
		})

		It("Close is idempotent across repeated calls", func() {
			s := newHTTP3Server(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
				&tls.Config{MinVersion: tls.VersionTLS13})

			Expect(s.Close()).Should(Succeed())
			Expect(s.Close()).Should(Succeed())
		})
	})

	Describe("newAltSvcMiddleware", func() {
		It("invokes the next handler", func() {
			h3 := newHTTP3Server(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
				&tls.Config{MinVersion: tls.VersionTLS13})

			called := false
			wrapped := newAltSvcMiddleware(h3)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			}))

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/dns-query", nil)
			wrapped.ServeHTTP(rec, req)

			Expect(called).To(BeTrue())
			Expect(rec.Code).To(Equal(http.StatusOK))
		})

		It("does not error when the inner server has no listeners (Alt-Svc may be empty)", func() {
			h3 := newHTTP3Server(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
				&tls.Config{MinVersion: tls.VersionTLS13})

			wrapped := newAltSvcMiddleware(h3)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/dns-query", nil)
			Expect(func() { wrapped.ServeHTTP(rec, req) }).ShouldNot(Panic())
		})

		It("populates the Alt-Svc header with h3= after Serve has bound a listener", func() {
			cert, err := util.TLSGenerateSelfSignedCert([]string{"localhost"})
			Expect(err).Should(Succeed())

			pc, err := net.ListenPacket("udp", "127.0.0.1:0")
			Expect(err).Should(Succeed())
			DeferCleanup(pc.Close)

			tlsCfg := newH3TLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}})
			h3 := newHTTP3Server(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), tlsCfg)
			DeferCleanup(h3.Close)

			go func() { _ = h3.inner.Serve(pc) }()

			wrapped := newAltSvcMiddleware(h3)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			Eventually(func(g Gomega) {
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				wrapped.ServeHTTP(rec, req)
				g.Expect(rec.Header().Get("Alt-Svc")).To(ContainSubstring("h3="))
			}, "2s", "20ms").Should(Succeed())
		})
	})

	Describe("newUDPPacketConns", func() {
		It("opens one UDP packet conn per address", func(ctx context.Context) {
			pcs, err := newUDPPacketConns(ctx, config.ListenConfig{"127.0.0.1:0", "127.0.0.1:0"})
			Expect(err).Should(Succeed())
			Expect(pcs).To(HaveLen(2))

			for _, pc := range pcs {
				addr, ok := pc.LocalAddr().(*net.UDPAddr)
				Expect(ok).To(BeTrue())
				Expect(addr.Port).ShouldNot(BeZero())
				_ = pc.Close()
			}
		})

		It("returns no conns for an empty address list", func(ctx context.Context) {
			pcs, err := newUDPPacketConns(ctx, config.ListenConfig{})
			Expect(err).Should(Succeed())
			Expect(pcs).To(BeEmpty())
		})

		It("returns a descriptive error for an invalid address", func(ctx context.Context) {
			_, err := newUDPPacketConns(ctx, config.ListenConfig{"not:a:valid:address"})
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("udp"))
		})
	})
})
