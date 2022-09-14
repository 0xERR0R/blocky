package resolver

import (
	"net"

	. "github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("SudnResolver", Label("sudnResolver"), func() {
	var (
		sut        *SpecialUseDomainNamesResolver
		m          *MockResolver
		mockAnswer *dns.Msg

		err  error
		resp *Response
	)

	BeforeEach(func() {
		mockAnswer, err = util.NewMsgWithAnswer("example.com.", 300, dns.Type(dns.TypeA), "123.145.123.145")
		Expect(err).Should(Succeed())

		m = &MockResolver{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: mockAnswer}, nil)

		sut = NewSpecialUseDomainNamesResolver().(*SpecialUseDomainNamesResolver)
		sut.Next(m)
	})

	Describe("Blocking special names", func() {
		It("should block arpa", func() {
			for _, arpa := range sudnArpaSlice() {
				resp, err = sut.Resolve(newRequest(arpa, dns.Type(dns.TypeA)))
				Expect(err).Should(Succeed())
				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeNameError))
			}
		})

		It("should block test", func() {
			resp, err = sut.Resolve(newRequest(sudnTest, dns.Type(dns.TypeA)))
			Expect(err).Should(Succeed())
			Expect(resp.Res.Rcode).Should(Equal(dns.RcodeNameError))
		})

		It("should block invalid", func() {
			resp, err = sut.Resolve(newRequest(sudnInvalid, dns.Type(dns.TypeA)))
			Expect(err).Should(Succeed())
			Expect(resp.Res.Rcode).Should(Equal(dns.RcodeNameError))
		})

		It("should block localhost none A", func() {
			resp, err = sut.Resolve(newRequest(sudnLocalhost, dns.Type(dns.TypeHTTPS)))
			Expect(err).Should(Succeed())
			Expect(resp.Res.Rcode).Should(Equal(dns.RcodeNameError))
		})

		It("should block local", func() {
			resp, err = sut.Resolve(newRequest(mdnsLocal, dns.Type(dns.TypeA)))
			Expect(err).Should(Succeed())
			Expect(resp.Res.Rcode).Should(Equal(dns.RcodeNameError))
		})

		It("should block localhost none A", func() {
			resp, err = sut.Resolve(newRequest(mdnsLocal, dns.Type(dns.TypeHTTPS)))
			Expect(err).Should(Succeed())
			Expect(resp.Res.Rcode).Should(Equal(dns.RcodeNameError))
		})
	})

	Describe("Resolve localhost", func() {
		It("should resolve IPv4 loopback", func() {
			resp, err = sut.Resolve(newRequest(sudnLocalhost, dns.Type(dns.TypeA)))
			Expect(err).Should(Succeed())
			Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
			Expect(resp.Res.Answer[0].(*dns.A).A).Should(Equal(sut.defaults.loopbackV4))
		})

		It("should resolve IPv6 loopback", func() {
			resp, err = sut.Resolve(newRequest(sudnLocalhost, dns.Type(dns.TypeAAAA)))
			Expect(err).Should(Succeed())
			Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
			Expect(resp.Res.Answer[0].(*dns.AAAA).AAAA).Should(Equal(sut.defaults.loopbackV6))
		})
	})

	Describe("Forward other", func() {
		It("should forward example.com", func() {
			resp, err = sut.Resolve(newRequest("example.com", dns.Type(dns.TypeA)))
			Expect(err).Should(Succeed())
			Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
			Expect(resp.Res.Answer[0].(*dns.A).A).Should(Equal(net.ParseIP("123.145.123.145")))
		})
	})

	Describe("Configuration pseudo test", func() {
		It("should always be empty", func() {
			Expect(sut.Configuration()).Should(HaveLen(0))
		})
	})
})
