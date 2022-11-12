package resolver

import (
	"strings"
	"time"

	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/helpertest"
	. "github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ParallelBestResolver", Label("parallelBestResolver"), func() {

	config.GetConfig().UpstreamTimeout = config.Duration(1000 * time.Millisecond)

	Describe("Default upstream resolvers are not defined", func() {
		It("should fail on startup", func() {

			_, err := NewParallelBestResolver(map[string][]config.Upstream{}, skipUpstreamCheck)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("no external DNS resolvers configured"))
		})
	})

	Describe("Some default upstream resolvers cannot be reached", func() {
		It("should start normally", func() {
			skipUpstreamCheck.startVerifyUpstream = true

			mockUpstream := NewMockUDPUpstreamServer().WithAnswerFn(func(request *dns.Msg) (response *dns.Msg) {
				response, _ = util.NewMsgWithAnswer(request.Question[0].Name, 123, dns.Type(dns.TypeA), "123.124.122.122")

				return
			})
			defer mockUpstream.Close()

			upstream := map[string][]config.Upstream{
				upstreamDefaultCfgName: {
					config.Upstream{
						Host: "wrong",
					},
					mockUpstream.Start(),
				},
			}

			_, err := NewParallelBestResolver(upstream, skipUpstreamCheck)
			Expect(err).Should(Not(HaveOccurred()))
		})
	})

	Describe("All default upstream resolvers cannot be reached", func() {
		var (
			upstream map[string][]config.Upstream
			b        *Bootstrap
		)

		BeforeEach(func() {
			b = TestBootstrap(&dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}})

			upstream = map[string][]config.Upstream{
				upstreamDefaultCfgName: {
					config.Upstream{
						Host: "wrong",
					},
					config.Upstream{
						Host: "127.0.0.2",
					},
				},
			}
		})

		It("should fail to start if strict checking is enabled", func() {
			b.startVerifyUpstream = true

			_, err := NewParallelBestResolver(upstream, b)
			Expect(err).Should(HaveOccurred())
		})

		It("should start if strict checking is disabled", func() {
			b.startVerifyUpstream = false

			_, err := NewParallelBestResolver(upstream, b)
			Expect(err).Should(Not(HaveOccurred()))
		})
	})

	Describe("Resolving result from fastest upstream resolver", func() {
		var (
			sut  Resolver
			err  error
			resp *Response
		)
		When("2 Upstream resolvers are defined", func() {
			When("one resolver is fast and another is slow", func() {
				BeforeEach(func() {
					fastTestUpstream := NewMockUDPUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.122")
					DeferCleanup(fastTestUpstream.Close)

					slowTestUpstream := NewMockUDPUpstreamServer().WithAnswerFn(func(request *dns.Msg) (response *dns.Msg) {
						response, err := util.NewMsgWithAnswer("example.com.", 123, dns.Type(dns.TypeA), "123.124.122.123")
						time.Sleep(50 * time.Millisecond)

						Expect(err).Should(Succeed())

						return response
					})
					DeferCleanup(slowTestUpstream.Close)

					sut, err = NewParallelBestResolver(map[string][]config.Upstream{
						upstreamDefaultCfgName: {fastTestUpstream.Start(), slowTestUpstream.Start()},
					}, skipUpstreamCheck)
					Expect(err).Should(Succeed())
				})
				It("Should use result from fastest one", func() {
					request := newRequest("example.com.", dns.Type(dns.TypeA))
					resp, err = sut.Resolve(request)

					Expect(err).Should(Succeed())

					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
					Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 123, "123.124.122.122"))
				})
			})
			When("one resolver is slow, but another returns an error", func() {
				BeforeEach(func() {
					withErrorUpstream := config.Upstream{Host: "wrong"}
					slowTestUpstream := NewMockUDPUpstreamServer().WithAnswerFn(func(request *dns.Msg) (response *dns.Msg) {
						response, err := util.NewMsgWithAnswer("example.com.", 123, dns.Type(dns.TypeA), "123.124.122.123")
						time.Sleep(50 * time.Millisecond)

						Expect(err).Should(Succeed())

						return response
					})
					DeferCleanup(slowTestUpstream.Close)
					sut, err = NewParallelBestResolver(map[string][]config.Upstream{
						upstreamDefaultCfgName: {withErrorUpstream, slowTestUpstream.Start()},
					}, skipUpstreamCheck)
					Expect(err).Should(Succeed())
				})
				It("Should use result from successful resolver", func() {
					request := newRequest("example.com.", dns.Type(dns.TypeA))
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

					sut, err = NewParallelBestResolver(map[string][]config.Upstream{
						upstreamDefaultCfgName: {withError1, withError2},
					}, skipUpstreamCheck)
					Expect(err).Should(Succeed())
				})
				It("Should return error", func() {
					request := newRequest("example.com.", dns.Type(dns.TypeA))
					resp, err = sut.Resolve(request)

					Expect(err).Should(HaveOccurred())
				})
			})

		})
		When("client specific resolvers are defined", func() {
			When("client name matches", func() {
				BeforeEach(func() {

					defaultMockUpstream := NewMockUDPUpstreamServer().
						WithAnswerRR("example.com 123 IN A 123.124.122.122")
					DeferCleanup(defaultMockUpstream.Close)

					clientSpecificExactMockUpstream := NewMockUDPUpstreamServer().
						WithAnswerRR("example.com 123 IN A 123.124.122.123")
					DeferCleanup(clientSpecificExactMockUpstream.Close)

					clientSpecificWildcardMockUpstream := NewMockUDPUpstreamServer().
						WithAnswerRR("example.com 123 IN A 123.124.122.124")
					DeferCleanup(clientSpecificWildcardMockUpstream.Close)

					clientSpecificIPMockUpstream := NewMockUDPUpstreamServer().
						WithAnswerRR("example.com 123 IN A 123.124.122.125")
					DeferCleanup(clientSpecificIPMockUpstream.Close)

					clientSpecificCIRDMockUpstream := NewMockUDPUpstreamServer().
						WithAnswerRR("example.com 123 IN A 123.124.122.126")
					DeferCleanup(clientSpecificCIRDMockUpstream.Close)

					sut, _ = NewParallelBestResolver(map[string][]config.Upstream{
						upstreamDefaultCfgName: {defaultMockUpstream.Start()},
						"laptop":               {clientSpecificExactMockUpstream.Start()},
						"client-*-m":           {clientSpecificWildcardMockUpstream.Start()},
						"client[0-9]":          {clientSpecificWildcardMockUpstream.Start()},
						"192.168.178.33":       {clientSpecificIPMockUpstream.Start()},
						"10.43.8.67/28":        {clientSpecificCIRDMockUpstream.Start()},
					}, skipUpstreamCheck)
				})
				It("Should use default if client name or IP don't match", func() {
					request := newRequestWithClient("example.com.", dns.Type(dns.TypeA), "192.168.178.55", "test")
					resp, err = sut.Resolve(request)

					Expect(err).Should(Succeed())
					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
					Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 123, "123.124.122.122"))
				})
				It("Should use client specific resolver if client name matches exact", func() {
					request := newRequestWithClient("example.com.", dns.Type(dns.TypeA), "192.168.178.55", "laptop")
					resp, err = sut.Resolve(request)

					Expect(err).Should(Succeed())
					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
					Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 123, "123.124.122.123"))
				})
				It("Should use client specific resolver if client name matches with wildcard", func() {
					request := newRequestWithClient("example.com.", dns.Type(dns.TypeA), "192.168.178.55", "client-test-m")
					resp, err = sut.Resolve(request)

					Expect(err).Should(Succeed())
					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
					Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 123, "123.124.122.124"))
				})
				It("Should use client specific resolver if client name matches with range wildcard", func() {
					request := newRequestWithClient("example.com.", dns.Type(dns.TypeA), "192.168.178.55", "client7")
					resp, err = sut.Resolve(request)

					Expect(err).Should(Succeed())
					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
					Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 123, "123.124.122.124"))
				})
				It("Should use client specific resolver if client IP matches", func() {
					request := newRequestWithClient("example.com.", dns.Type(dns.TypeA), "192.168.178.33", "cl")
					resp, err = sut.Resolve(request)

					Expect(err).Should(Succeed())
					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
					Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 123, "123.124.122.125"))
				})
				It("Should use client specific resolver if client's CIDR (10.43.8.64 - 10.43.8.79) matches", func() {
					request := newRequestWithClient("example.com.", dns.Type(dns.TypeA), "10.43.8.64", "cl")
					resp, err = sut.Resolve(request)

					Expect(err).Should(Succeed())
					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
					Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 123, "123.124.122.126"))
				})
			})
		})
		When("only 1 upstream resolvers is defined", func() {
			BeforeEach(func() {
				mockUpstream := NewMockUDPUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.122")
				DeferCleanup(mockUpstream.Close)

				sut, _ = NewParallelBestResolver(map[string][]config.Upstream{
					upstreamDefaultCfgName: {
						mockUpstream.Start(),
					},
				}, skipUpstreamCheck)
			})
			It("Should use result from defined resolver", func() {
				request := newRequest("example.com.", dns.Type(dns.TypeA))
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

				mockUpstream1 := NewMockUDPUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.122")
				DeferCleanup(mockUpstream1.Close)

				mockUpstream2 := NewMockUDPUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.122")
				DeferCleanup(mockUpstream2.Close)

				tmp, _ := NewParallelBestResolver(map[string][]config.Upstream{
					upstreamDefaultCfgName: {withError1, mockUpstream1.Start(), mockUpstream2.Start(), withError2},
				}, skipUpstreamCheck)
				sut := tmp.(*ParallelBestResolver)

				By("all resolvers have same weight for random -> equal distribution", func() {
					resolverCount := make(map[Resolver]int)

					for i := 0; i < 100; i++ {
						r1, r2 := pickRandom(sut.resolversForClient(newRequestWithClient(
							"example.com", dns.Type(dns.TypeA), "123.123.100.100",
						)))
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
						request := newRequest("example.com.", dns.Type(dns.TypeA))
						_, _ = sut.Resolve(request)
					}
				})

				By("Resolvers without errors should be selected often", func() {
					resolverCount := make(map[*UpstreamResolver]int)

					for i := 0; i < 100; i++ {
						r1, r2 := pickRandom(sut.resolversForClient(newRequestWithClient(
							"example.com", dns.Type(dns.TypeA), "123.123.100.100",
						)))
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

	When("upstream is invalid", func() {
		It("errors during construction", func() {
			b := TestBootstrap(&dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}})

			r, err := NewParallelBestResolver(map[string][]config.Upstream{"test": {{Host: "example.com"}}}, b)

			Expect(err).ShouldNot(Succeed())
			Expect(r).Should(BeNil())
		})
	})

	Describe("Configuration output", func() {
		var (
			sut Resolver
		)
		BeforeEach(func() {
			config.GetConfig().StartVerifyUpstream = false

			sut, _ = NewParallelBestResolver(map[string][]config.Upstream{upstreamDefaultCfgName: {
				{Host: "host1"},
				{Host: "host2"},
			}}, skipUpstreamCheck)
		})
		It("should return configuration", func() {
			c := sut.Configuration()
			Expect(len(c)).Should(BeNumerically(">", 1))
		})
	})

})
