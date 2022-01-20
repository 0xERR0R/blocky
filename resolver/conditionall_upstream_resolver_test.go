package resolver

import (
	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/log"
	. "github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("ConditionalUpstreamResolver", func() {
	var (
		sut  ChainedResolver
		m    *resolverMock
		err  error
		resp *Response
	)

	AfterEach(func() {
		Expect(err).Should(Succeed())
	})

	BeforeEach(func() {
		sut = NewConditionalUpstreamResolver(config.ConditionalUpstreamConfig{
			Rewrite: map[string]string{"example.com": "fritz.box"},
			Mapping: config.ConditionalUpstreamMapping{
				Upstreams: map[string][]config.Upstream{
					"fritz.box": {TestUDPUpstream(func(request *dns.Msg) (response *dns.Msg) {
						response, _ = util.NewMsgWithAnswer(request.Question[0].Name, 123, dns.TypeA, "123.124.122.122")

						return response
					})},
					"other.box": {TestUDPUpstream(func(request *dns.Msg) (response *dns.Msg) {
						response, _ = util.NewMsgWithAnswer(request.Question[0].Name, 250, dns.TypeA, "192.192.192.192")

						return response
					})},
					".": {TestUDPUpstream(func(request *dns.Msg) (response *dns.Msg) {
						response, _ = util.NewMsgWithAnswer(request.Question[0].Name, 223, dns.TypeA, "168.168.168.168")

						return response
					})},
				}},
		})
		m = &resolverMock{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
		sut.Next(m)
	})

	Describe("Resolve conditional DNS queries via defined DNS server", func() {
		When("Query is exact equal defined condition in mapping", func() {
			Context("first mapping entry", func() {
				It("Should resolve the IP of conditional DNS", func() {
					resp, err = sut.Resolve(newRequest("fritz.box.", dns.TypeA, logrus.NewEntry(log.Log())))

					Expect(resp.Res.Answer).Should(BeDNSRecord("fritz.box.", dns.TypeA, 123, "123.124.122.122"))
					// no call to next resolver
					Expect(m.Calls).Should(BeEmpty())
					Expect(resp.RType).Should(Equal(ResponseTypeCONDITIONAL))
				})
			})
			Context("last mapping entry", func() {
				It("Should resolve the IP of conditional DNS", func() {
					resp, err = sut.Resolve(newRequest("other.box.", dns.TypeA))

					Expect(resp.Res.Answer).Should(BeDNSRecord("other.box.", dns.TypeA, 250, "192.192.192.192"))
					// no call to next resolver
					Expect(m.Calls).Should(BeEmpty())
					Expect(resp.RType).Should(Equal(ResponseTypeCONDITIONAL))
				})
			})
		})
		When("Query is a subdomain of defined condition in mapping", func() {
			It("Should resolve the IP of subdomain", func() {
				resp, err = sut.Resolve(newRequest("test.fritz.box.", dns.TypeA))

				Expect(resp.Res.Answer).Should(BeDNSRecord("test.fritz.box.", dns.TypeA, 123, "123.124.122.122"))
				// no call to next resolver
				Expect(m.Calls).Should(BeEmpty())
				Expect(resp.RType).Should(Equal(ResponseTypeCONDITIONAL))
			})
		})
		When("Query is not fqdn and . condition is defined in mapping", func() {
			It("Should resolve the IP of .", func() {
				resp, err = sut.Resolve(newRequest("test.", dns.TypeA))

				Expect(resp.Res.Answer).Should(BeDNSRecord("test.", dns.TypeA, 223, "168.168.168.168"))
				// no call to next resolver
				Expect(m.Calls).Should(BeEmpty())
				Expect(resp.RType).Should(Equal(ResponseTypeCONDITIONAL))
			})
		})
		When("rewrite mapping is defined", func() {
			It("Should resolve the IP via defined resolver after applying the rewrite", func() {
				resp, err = sut.Resolve(newRequest("test.example.com.", dns.TypeA))

				Expect(resp.Res.Answer).Should(BeDNSRecord("test.fritz.box.", dns.TypeA, 123, "123.124.122.122"))
				// no call to next resolver
				Expect(m.Calls).Should(BeEmpty())
				Expect(resp.RType).Should(Equal(ResponseTypeCONDITIONAL))
			})

			It("Should delegate to next resolver if there is no subdomain after rewrite", func() {
				resp, err = sut.Resolve(newRequest("example.com.", dns.TypeA))

				m.AssertExpectations(GinkgoT())
			})
		})
	})
	Describe("Delegation to next resolver", func() {
		When("Query doesn't match defined mapping", func() {
			It("should delegate to next resolver", func() {
				resp, err = sut.Resolve(newRequest("google.com.", dns.TypeA))

				m.AssertExpectations(GinkgoT())
			})
		})
	})

	Describe("Configuration output", func() {
		When("resolver is enabled", func() {
			It("should return configuration", func() {
				c := sut.Configuration()
				Expect(len(c) > 1).Should(BeTrue())
			})
		})
		When("resolver is disabled", func() {
			BeforeEach(func() {
				sut = NewConditionalUpstreamResolver(config.ConditionalUpstreamConfig{})
			})
			It("should return 'disabled''", func() {
				c := sut.Configuration()
				Expect(c).Should(HaveLen(1))
				Expect(c).Should(Equal([]string{"deactivated"}))
			})
		})
	})
})
