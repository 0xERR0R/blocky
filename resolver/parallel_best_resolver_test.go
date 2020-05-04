package resolver

import (
	"blocky/config"
	. "blocky/helpertest"
	"blocky/util"
	"time"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ParallelBestResolver", func() {
	var (
		sut  Resolver
		err  error
		resp *Response
	)

	Describe("Resolving result from fastest upstream resolver", func() {
		When("2 Upstream resolvers are defined", func() {
			When("one resolver is fast and another is slow", func() {
				BeforeEach(func() {
					fast := TestUDPUpstream(func(request *dns.Msg) *dns.Msg {
						response, err := util.NewMsgWithAnswer("example.com.", 123, dns.TypeA, "123.124.122.122")

						Expect(err).Should(Succeed())
						return response
					})

					slow := TestUDPUpstream(func(request *dns.Msg) *dns.Msg {
						response, err := util.NewMsgWithAnswer("example.com.", 123, dns.TypeA, "123.124.122.123")
						time.Sleep(50 * time.Millisecond)

						Expect(err).Should(Succeed())
						return response
					})
					sut = NewParallelBestResolver(config.UpstreamConfig{
						ExternalResolvers: []config.Upstream{fast, slow},
					})
				})
				It("Should use result from fastest one", func() {
					request := newRequest("example.com.", dns.TypeA)
					resp, err = sut.Resolve(request)

					Expect(err).Should(Succeed())

					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.RType).Should(Equal(RESOLVED))
					Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 123, "123.124.122.122"))
				})
			})
			When("one resolver is slow, but another returns an error", func() {
				BeforeEach(func() {
					withError := config.Upstream{Host: "wrong"}

					slow := TestUDPUpstream(func(request *dns.Msg) *dns.Msg {
						response, err := util.NewMsgWithAnswer("example.com.", 123, dns.TypeA, "123.124.122.123")
						time.Sleep(50 * time.Millisecond)

						Expect(err).Should(Succeed())
						return response
					})
					sut = NewParallelBestResolver(config.UpstreamConfig{
						ExternalResolvers: []config.Upstream{withError, slow},
					})
				})
				It("Should use result from successful resolver", func() {
					request := newRequest("example.com.", dns.TypeA)
					resp, err = sut.Resolve(request)

					Expect(err).Should(Succeed())

					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.RType).Should(Equal(RESOLVED))
					Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 123, "123.124.122.123"))
				})
			})
			When("all resolvers return errors", func() {
				BeforeEach(func() {
					withError1 := config.Upstream{Host: "wrong"}
					withError2 := config.Upstream{Host: "wrong"}

					sut = NewParallelBestResolver(config.UpstreamConfig{
						ExternalResolvers: []config.Upstream{withError1, withError2},
					})
				})
				It("Should return error", func() {
					request := newRequest("example.com.", dns.TypeA)
					resp, err = sut.Resolve(request)

					Expect(err).Should(HaveOccurred())
				})
			})

		})
		When("only 1 upstream resolvers is defined", func() {
			BeforeEach(func() {
				fast := TestUDPUpstream(func(request *dns.Msg) *dns.Msg {
					response, err := util.NewMsgWithAnswer("example.com.", 123, dns.TypeA, "123.124.122.122")

					Expect(err).Should(Succeed())
					return response
				})
				sut = NewParallelBestResolver(config.UpstreamConfig{
					ExternalResolvers: []config.Upstream{fast},
				})
			})
			It("Should use result from defined resolver", func() {
				request := newRequest("example.com.", dns.TypeA)
				resp, err = sut.Resolve(request)

				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
				Expect(resp.RType).Should(Equal(RESOLVED))
				Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 123, "123.124.122.122"))
			})
		})
	})

	Describe("Configuration output", func() {
		BeforeEach(func() {
			sut = NewParallelBestResolver(config.UpstreamConfig{
				ExternalResolvers: []config.Upstream{
					{Host: "host1"},
					{Host: "host2"},
				},
			})
		})
		It("should return configuration", func() {
			c := sut.Configuration()
			Expect(len(c) > 1).Should(BeTrue())
		})
	})

})
