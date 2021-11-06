package resolver

import (
	"strings"
	"time"

	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/helpertest"
	. "github.com/0xERR0R/blocky/log"
	. "github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
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

	Describe("Default upstream resolvers are not defined", func() {
		It("should fail on startup", func() {
			defer func() { Log().ExitFunc = nil }()
			var fatal bool

			Log().ExitFunc = func(int) { fatal = true }

			sut = NewParallelBestResolver(map[string][]config.Upstream{})
			Expect(fatal).Should(BeTrue())
		})
	})

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
					sut = NewParallelBestResolver(map[string][]config.Upstream{upstreamDefaultCfgName: {fast, slow}})
				})
				It("Should use result from fastest one", func() {
					request := newRequest("example.com.", dns.TypeA)
					resp, err = sut.Resolve(request)

					Expect(err).Should(Succeed())

					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
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
					sut = NewParallelBestResolver(map[string][]config.Upstream{upstreamDefaultCfgName: {withError, slow}})
				})
				It("Should use result from successful resolver", func() {
					request := newRequest("example.com.", dns.TypeA)
					resp, err = sut.Resolve(request)

					Expect(err).Should(Succeed())

					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
					Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 123, "123.124.122.123"))
				})
			})
			When("all resolvers return errors", func() {
				BeforeEach(func() {
					withError1 := config.Upstream{Host: "wrong"}
					withError2 := config.Upstream{Host: "wrong"}

					sut = NewParallelBestResolver(map[string][]config.Upstream{upstreamDefaultCfgName: {withError1, withError2}})
				})
				It("Should return error", func() {
					request := newRequest("example.com.", dns.TypeA)
					resp, err = sut.Resolve(request)

					Expect(err).Should(HaveOccurred())
				})
			})

		})
		When("client specific resolvers are defined", func() {
			When("client name matches", func() {
				BeforeEach(func() {
					defaultResolver := TestUDPUpstream(func(request *dns.Msg) *dns.Msg {
						response, err := util.NewMsgWithAnswer("example.com.", 123, dns.TypeA, "123.124.122.122")

						Expect(err).Should(Succeed())
						return response
					})
					clientSpecificResolverExact := TestUDPUpstream(func(request *dns.Msg) *dns.Msg {
						response, err := util.NewMsgWithAnswer("example.com.", 123, dns.TypeA, "123.124.122.123")

						Expect(err).Should(Succeed())
						return response
					})
					clientSpecificResolverWildcard := TestUDPUpstream(func(request *dns.Msg) *dns.Msg {
						response, err := util.NewMsgWithAnswer("example.com.", 123, dns.TypeA, "123.124.122.124")
						time.Sleep(50 * time.Millisecond)

						Expect(err).Should(Succeed())
						return response
					})
					clientSpecificResolverIP := TestUDPUpstream(func(request *dns.Msg) *dns.Msg {
						response, err := util.NewMsgWithAnswer("example.com.", 123, dns.TypeA, "123.124.122.125")

						Expect(err).Should(Succeed())
						return response
					})
					clientSpecificResolverCIDR := TestUDPUpstream(func(request *dns.Msg) *dns.Msg {
						response, err := util.NewMsgWithAnswer("example.com.", 123, dns.TypeA, "123.124.122.126")

						Expect(err).Should(Succeed())
						return response
					})
					sut = NewParallelBestResolver(map[string][]config.Upstream{
						upstreamDefaultCfgNameDeprecated: {defaultResolver},
						"laptop":                         {clientSpecificResolverExact},
						"client-*-m":                     {clientSpecificResolverWildcard},
						"client[0-9]":                    {clientSpecificResolverWildcard},
						"192.168.178.33":                 {clientSpecificResolverIP},
						"10.43.8.67/28":                  {clientSpecificResolverCIDR},
					})
				})
				It("Should use default if client name or IP don't match", func() {
					request := newRequestWithClient("example.com.", dns.TypeA, "192.168.178.55", "test")
					resp, err = sut.Resolve(request)

					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
					Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 123, "123.124.122.122"))
				})
				It("Should use client specific resolver if client name matches exact", func() {
					request := newRequestWithClient("example.com.", dns.TypeA, "192.168.178.55", "laptop")
					resp, err = sut.Resolve(request)

					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
					Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 123, "123.124.122.123"))
				})
				It("Should use client specific resolver if client name matches with wildcard", func() {
					request := newRequestWithClient("example.com.", dns.TypeA, "192.168.178.55", "client-test-m")
					resp, err = sut.Resolve(request)

					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
					Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 123, "123.124.122.124"))
				})
				It("Should use client specific resolver if client name matches with range wildcard", func() {
					request := newRequestWithClient("example.com.", dns.TypeA, "192.168.178.55", "client7")
					resp, err = sut.Resolve(request)

					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
					Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 123, "123.124.122.124"))
				})
				It("Should use client specific resolver if client IP matches", func() {
					request := newRequestWithClient("example.com.", dns.TypeA, "192.168.178.33", "cl")
					resp, err = sut.Resolve(request)

					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
					Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 123, "123.124.122.125"))
				})
				It("Should use client specific resolver if client's CIDR (10.43.8.64 - 10.43.8.79) matches", func() {
					request := newRequestWithClient("example.com.", dns.TypeA, "10.43.8.64", "cl")
					resp, err = sut.Resolve(request)

					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
					Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 123, "123.124.122.126"))
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
				sut = NewParallelBestResolver(map[string][]config.Upstream{upstreamDefaultCfgName: {fast}})
			})
			It("Should use result from defined resolver", func() {
				request := newRequest("example.com.", dns.TypeA)
				resp, err = sut.Resolve(request)

				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
				Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
				Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 123, "123.124.122.122"))
			})
		})
	})

	Describe("Weighted random on resolver selection", func() {
		When("5 upstream resolvers are defined", func() {
			It("should use 2 random peeked resolvers, weighted with last error timestamp", func() {
				withError1 := config.Upstream{Host: "wrong1"}
				withError2 := config.Upstream{Host: "wrong2"}
				fast1 := TestUDPUpstream(func(request *dns.Msg) *dns.Msg {
					response, err := util.NewMsgWithAnswer("example.com.", 123, dns.TypeA, "123.124.122.122")

					Expect(err).Should(Succeed())
					return response
				})
				fast2 := TestUDPUpstream(func(request *dns.Msg) *dns.Msg {
					response, err := util.NewMsgWithAnswer("example.com.", 123, dns.TypeA, "123.124.122.122")

					Expect(err).Should(Succeed())
					return response
				})

				sut := NewParallelBestResolver(map[string][]config.Upstream{
					upstreamDefaultCfgName: {withError1, fast1, fast2, withError2},
				}).(*ParallelBestResolver)

				By("all resolvers have same weight for random -> equal distribution", func() {
					resolverCount := make(map[Resolver]int)

					for i := 0; i < 100; i++ {
						r1, r2 := pickRandom(sut.resolversForClient(newRequestWithClient("example.com", dns.TypeA, "123.123.100.100")))
						res1 := r1.resolver
						res2 := r2.resolver
						Expect(res1).ShouldNot(Equal(res2))

						resolverCount[res1]++
						resolverCount[res2]++
					}
					for _, v := range resolverCount {
						// should be 50 ± 10
						Expect(v).Should(BeNumerically("~", 50, 10))
					}
				})
				By("perform 10 request, error upstream's weight will be reduced", func() {
					// perform 10 requests
					for i := 0; i < 100; i++ {
						request := newRequest("example.com.", dns.TypeA)
						_, _ = sut.Resolve(request)
					}
				})

				By("Resolvers without errors should be selected often", func() {
					resolverCount := make(map[*UpstreamResolver]int)

					for i := 0; i < 100; i++ {
						r1, r2 := pickRandom(sut.resolversForClient(newRequestWithClient("example.com", dns.TypeA, "123.123.100.100")))
						res1 := r1.resolver.(*UpstreamResolver)
						res2 := r2.resolver.(*UpstreamResolver)
						Expect(res1).ShouldNot(Equal(res2))

						resolverCount[res1]++
						resolverCount[res2]++
					}
					for k, v := range resolverCount {
						if strings.Contains(k.String(), "wrong") {
							// error resolvers: should be 0 - 10
							Expect(v).Should(BeNumerically("~", 0, 10))
						} else {
							// should be 90 ± 10
							Expect(v).Should(BeNumerically("~", 90, 10))
						}
					}
				})
			})
		})
	})

	Describe("Configuration output", func() {
		BeforeEach(func() {
			sut = NewParallelBestResolver(map[string][]config.Upstream{upstreamDefaultCfgName: {
				{Host: "host1"},
				{Host: "host2"},
			}})
		})
		It("should return configuration", func() {
			c := sut.Configuration()
			Expect(len(c) > 1).Should(BeTrue())
		})
	})

})
