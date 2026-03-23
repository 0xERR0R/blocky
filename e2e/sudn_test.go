package e2e

import (
	"context"

	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

var _ = Describe("Special Use Domain Names (SUDN)", func() {
	var (
		e2eNet *testcontainers.DockerNetwork
		blocky testcontainers.Container
		err    error
	)

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)

		_, err = createDNSMokkaContainer(ctx, "moka", e2eNet,
			`A something.localhost/NOERROR("A 1.2.3.4 300")`,
			`A something.invalid/NOERROR("A 1.2.3.4 300")`,
			`A mydevice.local/NOERROR("A 1.2.3.4 300")`,
			`A myhost.lan/NOERROR("A 1.2.3.4 300")`,
			`A myhost.internal/NOERROR("A 1.2.3.4 300")`,
			`A myhost.home/NOERROR("A 1.2.3.4 300")`,
			`A myhost.corp/NOERROR("A 1.2.3.4 300")`,
			`A google.com/NOERROR("A 8.8.8.8 300")`,
		)
		Expect(err).Should(Succeed())
	})

	Describe("RFC 6761 reserved domains", func() {
		When("SUDN is enabled (default)", func() {
			BeforeEach(func(ctx context.Context) {
				blocky, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
					upstreams:
					  groups:
					    default:
					      - moka
					`))
				Expect(err).Should(Succeed())
			})

			It("should handle .localhost locally and return loopback", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("something.localhost.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(BeDNSRecord("something.localhost.", A, "127.0.0.1"))
			})

			It("should return NXDOMAIN for .invalid", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("something.invalid.", A)
				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())
				Expect(resp.Rcode).Should(Equal(dns.RcodeNameError))
			})

			It("should handle PTR for private ranges locally", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("1.0.168.192.in-addr.arpa.", dns.Type(dns.TypePTR))
				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())
				Expect(resp.Rcode).ShouldNot(Equal(dns.RcodeServerFailure))
			})
		})
	})

	Describe("RFC 6762 mDNS", func() {
		When("SUDN is enabled (default)", func() {
			BeforeEach(func(ctx context.Context) {
				blocky, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
					upstreams:
					  groups:
					    default:
					      - moka
					`))
				Expect(err).Should(Succeed())
			})

			It("should block .local domains (not forward to upstream)", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("mydevice.local.", A)
				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())
				Expect(resp.Answer).ShouldNot(ContainElement(BeDNSRecord("mydevice.local.", A, "1.2.3.4")))
			})
		})
	})

	Describe("RFC 6762 Appendix G TLDs", func() {
		When("rfc6762-appendixG is enabled (default)", func() {
			BeforeEach(func(ctx context.Context) {
				blocky, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
					upstreams:
					  groups:
					    default:
					      - moka
					`))
				Expect(err).Should(Succeed())
			})

			It("should block .lan domains", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("myhost.lan.", A)
				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())
				Expect(resp.Rcode).Should(Equal(dns.RcodeNameError))
			})

			It("should block .internal domains", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("myhost.internal.", A)
				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())
				Expect(resp.Rcode).Should(Equal(dns.RcodeNameError))
			})

			It("should block .home domains", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("myhost.home.", A)
				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())
				Expect(resp.Rcode).Should(Equal(dns.RcodeNameError))
			})

			It("should block .corp domains", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("myhost.corp.", A)
				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())
				Expect(resp.Rcode).Should(Equal(dns.RcodeNameError))
			})

			It("should still resolve normal domains via upstream", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("google.com.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(BeDNSRecord("google.com.", A, "8.8.8.8"))
			})
		})
	})

	Describe("SUDN disabled", func() {
		When("SUDN is completely disabled", func() {
			BeforeEach(func(ctx context.Context) {
				blocky, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
					upstreams:
					  groups:
					    default:
					      - moka
					specialUseDomains:
					  enable: false
					`))
				Expect(err).Should(Succeed())
			})

			It("should forward .invalid to upstream", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("something.invalid.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(BeDNSRecord("something.invalid.", A, "1.2.3.4"))
			})

			It("should forward .lan to upstream", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("myhost.lan.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(BeDNSRecord("myhost.lan.", A, "1.2.3.4"))
			})
		})
	})

	Describe("Partial config", func() {
		When("base SUDN enabled but Appendix G disabled", func() {
			BeforeEach(func(ctx context.Context) {
				blocky, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
					upstreams:
					  groups:
					    default:
					      - moka
					specialUseDomains:
					  rfc6762-appendixG: false
					`))
				Expect(err).Should(Succeed())
			})

			It("should still handle RFC 6761 domains locally", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("something.invalid.", A)
				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())
				Expect(resp.Rcode).Should(Equal(dns.RcodeNameError))
			})

			It("should forward Appendix G TLDs to upstream", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("myhost.lan.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(BeDNSRecord("myhost.lan.", A, "1.2.3.4"))
			})

			It("should forward .home to upstream", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("myhost.home.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(BeDNSRecord("myhost.home.", A, "1.2.3.4"))
			})
		})
	})
})
