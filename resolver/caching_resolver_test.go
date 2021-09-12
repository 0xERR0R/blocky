package resolver

import (
	"time"

	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/evt"
	. "github.com/0xERR0R/blocky/helpertest"
	. "github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"

	"github.com/0xERR0R/go-cache"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("CachingResolver", func() {
	var (
		sut        ChainedResolver
		sutConfig  config.CachingConfig
		m          *resolverMock
		mockAnswer *dns.Msg

		err  error
		resp *Response
	)

	BeforeEach(func() {
		sutConfig = config.CachingConfig{}
		mockAnswer = new(dns.Msg)

	})

	AfterEach(func() {
		Expect(err).Should(Succeed())
	})

	JustBeforeEach(func() {
		sut = NewCachingResolver(sutConfig)
		m = &resolverMock{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: mockAnswer}, nil)
		sut.Next(m)
	})

	Describe("Caching responses", func() {
		When("prefetching is enabled", func() {
			BeforeEach(func() {
				sutConfig = config.CachingConfig{
					Prefetching:       true,
					PrefetchExpires:   config.Duration(time.Minute * 120),
					PrefetchThreshold: 5,
				}
			})

			It("should prefetch domain if query count > threshold", func() {
				// prepare resolver, set smaller caching times for testing
				prefetchThreshold := 5
				sut.(*CachingResolver).resultCache = cache.New(25*time.Millisecond, 15*time.Millisecond)
				configurePrefetching(sut.(*CachingResolver), &sutConfig)

				prefetchedCnt := 0
				_ = Bus().SubscribeOnce(CachingDomainsToPrefetchCountChanged, func(cnt int) {
					prefetchedCnt = cnt
				})

				prefetchHitDomain := ""
				_ = Bus().SubscribeOnce(CachingPrefetchCacheHit, func(domain string) {
					prefetchHitDomain = domain
				})

				domainPrefetched := ""
				_ = Bus().SubscribeOnce(CachingDomainPrefetched, func(domain string) {
					domainPrefetched = domain
				})

				// first request
				_, _ = sut.Resolve(newRequest("example.com.", dns.TypeA))

				// Domain is not prefetched
				Expect(domainPrefetched).Should(Equal(""))

				// Domain is in prefetched domain cache
				Expect(prefetchedCnt).Should(Equal(1))

				// now query again > threshold
				for i := 0; i < prefetchThreshold; i++ {
					_, _ = sut.Resolve(newRequest("example.com.", dns.TypeA))

				}
				time.Sleep(50 * time.Millisecond)

				// now is this domain prefetched
				Expect(domainPrefetched).Should(Equal("example.com"))

				// and it should hit from prefetch cache
				_, _ = sut.Resolve(newRequest("example.com.", dns.TypeA))
				Expect(prefetchHitDomain).Should(Equal("example.com"))
			})
		})
		When("min caching time is defined", func() {
			BeforeEach(func() {
				sutConfig = config.CachingConfig{
					MinCachingTime: config.Duration(time.Minute * 5),
				}
			})
			Context("response TTL is bigger than defined min caching time", func() {
				BeforeEach(func() {
					mockAnswer, _ = util.NewMsgWithAnswer("example.com.", 600, dns.TypeA, "123.122.121.120")
				})

				It("should cache response and use response's TTL", func() {

					By("first request", func() {
						domain := ""
						_ = Bus().SubscribeOnce(CachingResultCacheMiss, func(d string) {
							domain = d
						})

						totalCacheCount := 0
						_ = Bus().SubscribeOnce(CachingResultCacheChanged, func(d int) {
							totalCacheCount = d
						})

						resp, err = sut.Resolve(newRequest("example.com.", dns.TypeA))
						Expect(err).Should(Succeed())
						Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
						Expect(m.Calls).Should(HaveLen(1))
						Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
						Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 600, "123.122.121.120"))

						Expect(domain).Should(Equal("example.com"))
						Expect(totalCacheCount).Should(Equal(1))
					})

					time.Sleep(500 * time.Millisecond)

					By("second request", func() {
						domain := ""
						_ = Bus().SubscribeOnce(CachingResultCacheHit, func(d string) {
							domain = d
						})

						resp, err = sut.Resolve(newRequest("example.com.", dns.TypeA))
						Expect(err).Should(Succeed())
						Expect(resp.RType).Should(Equal(ResponseTypeCACHED))
						// still one call to upstream
						Expect(m.Calls).Should(HaveLen(1))
						Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
						// ttl is smaller
						Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 599, "123.122.121.120"))

						Expect(domain).Should(Equal("example.com"))
					})
				})
			})
			Context("response TTL is smaller than defined min caching time", func() {
				Context("A query", func() {
					BeforeEach(func() {
						mockAnswer, _ = util.NewMsgWithAnswer("example.com.", 123, dns.TypeA, "123.122.121.120")
					})

					It("should cache response and use min caching time as TTL", func() {

						By("first request", func() {
							resp, err = sut.Resolve(newRequest("example.com.", dns.TypeA))
							Expect(err).Should(Succeed())
							Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
							Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
							Expect(m.Calls).Should(HaveLen(1))
							Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 300, "123.122.121.120"))
						})

						time.Sleep(500 * time.Millisecond)

						By("second request", func() {
							resp, err = sut.Resolve(newRequest("example.com.", dns.TypeA))
							Expect(err).Should(Succeed())
							Expect(resp.RType).Should(Equal(ResponseTypeCACHED))
							Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
							// still one call to upstream
							Expect(m.Calls).Should(HaveLen(1))
							// ttl is smaller
							Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 299, "123.122.121.120"))
						})
					})
				})

				Context("AAAA query", func() {
					BeforeEach(func() {
						mockAnswer, _ = util.NewMsgWithAnswer("example.com.", 123,
							dns.TypeAAAA, "2001:0db8:85a3:08d3:1319:8a2e:0370:7344")
					})

					It("should cache response and use min caching time as TTL", func() {

						By("first request", func() {
							resp, err = sut.Resolve(newRequest("example.com.", dns.TypeAAAA))
							Expect(err).Should(Succeed())
							Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
							Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
							Expect(m.Calls).Should(HaveLen(1))
							Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.",
								dns.TypeAAAA, 300, "2001:db8:85a3:8d3:1319:8a2e:370:7344"))
						})

						time.Sleep(500 * time.Millisecond)

						By("second request", func() {
							resp, err = sut.Resolve(newRequest("example.com.", dns.TypeAAAA))
							Expect(err).Should(Succeed())
							Expect(resp.RType).Should(Equal(ResponseTypeCACHED))
							Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
							// still one call to upstream
							Expect(m.Calls).Should(HaveLen(1))
							// ttl is smaller
							Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.",
								dns.TypeAAAA, 299, "2001:db8:85a3:8d3:1319:8a2e:370:7344"))
						})
					})
				})

			})

		})
		When("max caching time is defined", func() {

			BeforeEach(func() {
				mockAnswer, _ = util.NewMsgWithAnswer("example.com.", 1230, dns.TypeAAAA, "2001:0db8:85a3:08d3:1319:8a2e:0370:7344")
			})
			Context("max caching time is negative -> caching is disabled", func() {
				BeforeEach(func() {
					sutConfig = config.CachingConfig{
						MaxCachingTime: config.Duration(time.Minute * -1),
					}
				})

				It("Shouldn't cache any responses", func() {
					By("first request", func() {
						resp, err = sut.Resolve(newRequest("example.com.", dns.TypeAAAA))
						Expect(err).Should(Succeed())
						Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
						Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
						Expect(m.Calls).Should(HaveLen(1))
						Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.",
							dns.TypeAAAA, 1230, "2001:db8:85a3:8d3:1319:8a2e:370:7344"))
					})

					time.Sleep(500 * time.Millisecond)

					By("second request", func() {
						resp, err = sut.Resolve(newRequest("example.com.", dns.TypeAAAA))
						Expect(err).Should(Succeed())
						Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
						Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
						//  one more call to upstream
						Expect(m.Calls).Should(HaveLen(2))
						Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.",
							dns.TypeAAAA, 1230, "2001:db8:85a3:8d3:1319:8a2e:370:7344"))
					})
				})
			})

			Context("max caching time is positive", func() {
				BeforeEach(func() {
					sutConfig = config.CachingConfig{
						MaxCachingTime: config.Duration(time.Minute * 4),
					}
				})
				It("should cache response and use max caching time as TTL if response TTL is bigger", func() {
					By("first request", func() {
						resp, err = sut.Resolve(newRequest("example.com.", dns.TypeAAAA))
						Expect(err).Should(Succeed())
						Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
						Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
						Expect(m.Calls).Should(HaveLen(1))
						Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.",
							dns.TypeAAAA, 240, "2001:db8:85a3:8d3:1319:8a2e:370:7344"))
					})

					time.Sleep(500 * time.Millisecond)

					By("second request", func() {
						resp, err = sut.Resolve(newRequest("example.com.", dns.TypeAAAA))
						Expect(err).Should(Succeed())
						Expect(resp.RType).Should(Equal(ResponseTypeCACHED))
						Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
						// still one call to upstream
						Expect(m.Calls).Should(HaveLen(1))
						// ttl is smaller
						Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.",
							dns.TypeAAAA, 239, "2001:db8:85a3:8d3:1319:8a2e:370:7344"))
					})
				})
			})
		})
	})

	Describe("Negative cache (caching if upstream resolver returns NXDOMAIN)", func() {
		When("Upstream resolver returns NXDOMAIN", func() {
			BeforeEach(func() {
				mockAnswer.Rcode = dns.RcodeNameError
			})

			It("response should be cached", func() {
				By("first request", func() {
					resp, err = sut.Resolve(newRequest("example.com.", dns.TypeAAAA))
					Expect(err).Should(Succeed())
					Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeNameError))
					Expect(m.Calls).Should(HaveLen(1))
				})

				time.Sleep(500 * time.Millisecond)

				By("second request", func() {
					resp, err = sut.Resolve(newRequest("example.com.", dns.TypeAAAA))
					Expect(err).Should(Succeed())
					Expect(resp.RType).Should(Equal(ResponseTypeCACHED))
					Expect(resp.Reason).Should(Equal("CACHED NEGATIVE"))
					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeNameError))
					// still one call to resolver
					Expect(m.Calls).Should(HaveLen(1))
				})
			})

		})
	})

	Describe("Not A / AAAA queries should also cached", func() {
		When("MX query will be performed", func() {
			BeforeEach(func() {
				mockAnswer, _ = util.NewMsgWithAnswer("google.de.", 180, dns.TypeMX, "10 alt1.aspmx.l.google.com.")
			})
			It("Should be cached", func() {
				By("first request", func() {
					resp, err = sut.Resolve(newRequest("google.de.", dns.TypeMX))
					Expect(err).Should(Succeed())
					Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(m.Calls).Should(HaveLen(1))
					Expect(resp.Res.Answer).Should(BeDNSRecord("google.de.", dns.TypeMX, 180, "alt1.aspmx.l.google.com."))
				})

				By("second request", func() {
					resp, err = sut.Resolve(newRequest("google.de.", dns.TypeMX))
					Expect(err).Should(Succeed())
					Expect(resp.RType).Should(Equal(ResponseTypeCACHED))
					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(m.Calls).Should(HaveLen(1))
					Expect(resp.Res.Answer).Should(BeDNSRecord("google.de.", dns.TypeMX, 179, "alt1.aspmx.l.google.com."))
				})
			})
		})
	})

	Describe("Configuration output", func() {
		When("resolver is enabled", func() {
			BeforeEach(func() {
				sutConfig = config.CachingConfig{}
			})
			It("should return configuration", func() {
				c := sut.Configuration()
				Expect(len(c) > 1).Should(BeTrue())
			})
		})

		When("resolver is disabled", func() {
			BeforeEach(func() {
				sutConfig = config.CachingConfig{
					MaxCachingTime: config.Duration(time.Minute * -1),
				}
			})
			It("should return 'disabled''", func() {
				c := sut.Configuration()
				Expect(c).Should(HaveLen(1))
				Expect(c).Should(Equal([]string{"deactivated"}))
			})
		})

		When("prefetching is enabled", func() {
			BeforeEach(func() {
				sutConfig = config.CachingConfig{
					Prefetching: true,
				}
			})
			It("should return configuration", func() {
				c := sut.Configuration()
				Expect(len(c) > 1).Should(BeTrue())
				Expect(c).Should(ContainElement(ContainSubstring("prefetchThreshold")))
			})
		})
	})
})
