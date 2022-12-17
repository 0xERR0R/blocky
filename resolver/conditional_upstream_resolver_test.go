package resolver

import (
	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/log"
	. "github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("ConditionalUpstreamResolver", Label("conditionalResolver"), func() {
	var (
		sut  ChainedResolver
		m    *mockResolver
		err  error
		resp *Response
	)

	AfterEach(func() {
		Expect(err).Should(Succeed())
	})

	BeforeEach(func() {
		fbTestUpstream := NewMockUDPUpstreamServer().WithAnswerFn(func(request *dns.Msg) (response *dns.Msg) {
			response, _ = util.NewMsgWithAnswer(request.Question[0].Name, 123, dns.Type(dns.TypeA), "123.124.122.122")

			return response
		})
		DeferCleanup(fbTestUpstream.Close)

		otherTestUpstream := NewMockUDPUpstreamServer().WithAnswerFn(func(request *dns.Msg) (response *dns.Msg) {
			response, _ = util.NewMsgWithAnswer(request.Question[0].Name, 250, dns.Type(dns.TypeA), "192.192.192.192")

			return response
		})
		DeferCleanup(otherTestUpstream.Close)

		dotTestUpstream := NewMockUDPUpstreamServer().WithAnswerFn(func(request *dns.Msg) (response *dns.Msg) {
			response, _ = util.NewMsgWithAnswer(request.Question[0].Name, 223, dns.Type(dns.TypeA), "168.168.168.168")

			return response
		})
		DeferCleanup(dotTestUpstream.Close)

		sut, _ = NewConditionalUpstreamResolver(config.ConditionalUpstreamConfig{
			Mapping: config.ConditionalUpstreamMapping{
				Upstreams: map[string][]config.Upstream{
					"fritz.box": {fbTestUpstream.Start()},
					"other.box": {otherTestUpstream.Start()},
					".":         {dotTestUpstream.Start()},
				}},
		}, nil, false)
		m = &mockResolver{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
		sut.Next(m)
	})

	Describe("Resolve conditional DNS queries via defined DNS server", func() {
		When("Query is exact equal defined condition in mapping", func() {
			Context("first mapping entry", func() {
				It("Should resolve the IP of conditional DNS", func() {
					resp, err = sut.Resolve(newRequest("fritz.box.", dns.Type(dns.TypeA), logrus.NewEntry(log.Log())))

					Expect(resp.Res.Answer).Should(BeDNSRecord("fritz.box.", dns.TypeA, 123, "123.124.122.122"))
					// no call to next resolver
					Expect(m.Calls).Should(BeEmpty())
					Expect(resp.RType).Should(Equal(ResponseTypeCONDITIONAL))
				})
			})
			Context("last mapping entry", func() {
				It("Should resolve the IP of conditional DNS", func() {
					resp, err = sut.Resolve(newRequest("other.box.", dns.Type(dns.TypeA)))

					Expect(resp.Res.Answer).Should(BeDNSRecord("other.box.", dns.TypeA, 250, "192.192.192.192"))
					// no call to next resolver
					Expect(m.Calls).Should(BeEmpty())
					Expect(resp.RType).Should(Equal(ResponseTypeCONDITIONAL))
				})
			})
		})
		When("Query is a subdomain of defined condition in mapping", func() {
			It("Should resolve the IP of subdomain", func() {
				resp, err = sut.Resolve(newRequest("test.fritz.box.", dns.Type(dns.TypeA)))

				Expect(resp.Res.Answer).Should(BeDNSRecord("test.fritz.box.", dns.TypeA, 123, "123.124.122.122"))
				// no call to next resolver
				Expect(m.Calls).Should(BeEmpty())
				Expect(resp.RType).Should(Equal(ResponseTypeCONDITIONAL))
			})
		})
		When("Query is not fqdn and . condition is defined in mapping", func() {
			It("Should resolve the IP of .", func() {
				resp, err = sut.Resolve(newRequest("test.", dns.Type(dns.TypeA)))

				Expect(resp.Res.Answer).Should(BeDNSRecord("test.", dns.TypeA, 223, "168.168.168.168"))
				// no call to next resolver
				Expect(m.Calls).Should(BeEmpty())
				Expect(resp.RType).Should(Equal(ResponseTypeCONDITIONAL))
			})
		})
	})
	Describe("Delegation to next resolver", func() {
		When("Query doesn't match defined mapping", func() {
			It("should delegate to next resolver", func() {
				resp, err = sut.Resolve(newRequest("google.com.", dns.Type(dns.TypeA)))

				m.AssertExpectations(GinkgoT())
			})
		})
	})

	When("upstream is invalid", func() {
		It("errors during construction", func() {
			b := newTestBootstrap(&dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}})

			r, err := NewConditionalUpstreamResolver(config.ConditionalUpstreamConfig{
				Mapping: config.ConditionalUpstreamMapping{
					Upstreams: map[string][]config.Upstream{
						".": {config.Upstream{Host: "example.com"}},
					},
				},
			}, b, true)

			Expect(err).ShouldNot(Succeed())
			Expect(r).Should(BeNil())
		})
	})

	Describe("Configuration output", func() {
		When("resolver is enabled", func() {
			It("should return configuration", func() {
				c := sut.Configuration()
				Expect(len(c)).Should(BeNumerically(">", 1))
			})
		})
		When("resolver is disabled", func() {
			BeforeEach(func() {
				sut, _ = NewConditionalUpstreamResolver(config.ConditionalUpstreamConfig{}, nil, false)
			})
			It("should return 'disabled'", func() {
				c := sut.Configuration()
				Expect(c).Should(ContainElement(configStatusDisabled))
			})
		})
	})
})
