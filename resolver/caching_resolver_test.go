package resolver

import (
	"time"

	"github.com/0xERR0R/blocky/cache/expirationcache"
	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/evt"
	. "github.com/0xERR0R/blocky/helpertest"
	. "github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/redis"
	"github.com/0xERR0R/blocky/util"
	"github.com/alicebob/miniredis/v2"
	"github.com/creasty/defaults"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("CachingResolver", func() {
	var (
		sut        ChainedResolver
		sutConfig  config.CachingConfig
		m          *mockResolver
		mockAnswer *dns.Msg

		err  error
		resp *Response
	)

	BeforeEach(func() {
		sutConfig = config.CachingConfig{}
		if err := defaults.Set(&sutConfig); err != nil {
			panic(err)
		}
		mockAnswer = new(dns.Msg)

	})

	AfterEach(func() {
		Expect(err).Should(Succeed())
	})

	JustBeforeEach(func() {
		sut = NewCachingResolver(sutConfig, nil)
		m = &mockResolver{}
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
				mockAnswer, _ = util.NewMsgWithAnswer("example.com.", 2, dns.Type(dns.TypeA), "123.122.121.120")
			})

			It("should prefetch domain if query count > threshold", func() {
				// prepare resolver, set smaller caching times for testing
				prefetchThreshold := 5
				configureCaches(sut.(*CachingResolver), &sutConfig)
				sut.(*CachingResolver).resultCache = expirationcache.NewCache(
					expirationcache.WithCleanUpInterval(100*time.Millisecond),
					expirationcache.WithOnExpiredFn(sut.(*CachingResolver).onExpired))

				domainPrefetched := make(chan string, 1)
				prefetchHitDomain := make(chan string, 1)
				prefetchedCnt := make(chan int, 1)
				Expect(Bus().SubscribeOnce(CachingPrefetchCacheHit, func(domain string) {
					prefetchHitDomain <- domain
				})).Should(Succeed())
				Expect(Bus().SubscribeOnce(CachingDomainPrefetched, func(domain string) {
					domainPrefetched <- domain
				})).Should(Succeed())

				Expect(Bus().SubscribeOnce(CachingDomainsToPrefetchCountChanged, func(cnt int) {
					prefetchedCnt <- cnt
				})).Should(Succeed())

				// first request
				_, _ = sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeA)))

				// Domain is not prefetched
				Expect(domainPrefetched).ShouldNot(Receive())

				// Domain is in prefetched domain cache
				Expect(prefetchedCnt).Should(Receive(Equal(1)))

				// now query again > threshold
				for i := 0; i < prefetchThreshold+1; i++ {
					_, err = sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeA)))
					Expect(err).Should(Succeed())
				}

				// now is this domain prefetched
				Eventually(domainPrefetched, "4s").Should(Receive(Equal("example.com")))

				// and it should hit from prefetch cache
				res, err := sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeA)))
				Expect(res.RType).Should(Equal(ResponseTypeCACHED))
				Expect(res.Res.Rcode).Should(Equal(dns.RcodeSuccess))
				Expect(err).Should(Succeed())
				Eventually(prefetchHitDomain, "4s").Should(Receive(Equal("example.com")))

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
					mockAnswer, _ = util.NewMsgWithAnswer("example.com.", 600, dns.Type(dns.TypeA), "123.122.121.120")
				})

				It("should cache response and use response's TTL", func() {

					By("first request", func() {
						domain := make(chan string, 1)
						_ = Bus().SubscribeOnce(CachingResultCacheMiss, func(d string) {
							domain <- d
						})

						totalCacheCount := make(chan int, 1)
						_ = Bus().SubscribeOnce(CachingResultCacheChanged, func(d int) {
							totalCacheCount <- d
						})

						resp, err = sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeA)))
						Expect(err).Should(Succeed())
						Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
						Expect(m.Calls).Should(HaveLen(1))
						Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
						Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 600, "123.122.121.120"))

						Expect(domain).Should(Receive(Equal("example.com")))
						Expect(totalCacheCount).Should(Receive(Equal(1)))

					})

					By("second request", func() {
						Eventually(func(g Gomega) {
							domain := make(chan string, 1)
							_ = Bus().SubscribeOnce(CachingResultCacheHit, func(d string) {
								domain <- d
							})

							resp, err = sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeA)))
							g.Expect(err).Should(Succeed())
							g.Expect(resp.RType).Should(Equal(ResponseTypeCACHED))
							// still one call to upstream
							g.Expect(m.Calls).Should(HaveLen(1))
							g.Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
							// ttl is smaller
							g.Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 599, "123.122.121.120"))

							g.Expect(domain).Should(Receive(Equal("example.com")))
						}, "1s").Should(Succeed())

					})
				})
			})
			Context("response TTL is smaller than defined min caching time", func() {
				Context("A query", func() {
					BeforeEach(func() {
						mockAnswer, _ = util.NewMsgWithAnswer("example.com.", 123, dns.Type(dns.TypeA), "123.122.121.120")
					})

					It("should cache response and use min caching time as TTL", func() {

						By("first request", func() {
							resp, err = sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeA)))
							Expect(err).Should(Succeed())
							Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
							Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
							Expect(m.Calls).Should(HaveLen(1))
							Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 300, "123.122.121.120"))
						})

						By("second request", func() {
							Eventually(func(g Gomega) {
								resp, err = sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeA)))
								g.Expect(err).Should(Succeed())
								g.Expect(resp.RType).Should(Equal(ResponseTypeCACHED))
								g.Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
								// still one call to upstream
								g.Expect(m.Calls).Should(HaveLen(1))
								// ttl is smaller
								g.Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 299, "123.122.121.120"))
							}, "500ms").Should(Succeed())
						})
					})
				})

				Context("AAAA query", func() {
					BeforeEach(func() {
						mockAnswer, _ = util.NewMsgWithAnswer("example.com.", 123,
							dns.Type(dns.TypeAAAA), "2001:0db8:85a3:08d3:1319:8a2e:0370:7344")
					})

					It("should cache response and use min caching time as TTL", func() {

						By("first request", func() {
							resp, err = sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeAAAA)))
							Expect(err).Should(Succeed())
							Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
							Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
							Expect(m.Calls).Should(HaveLen(1))
							Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.",
								dns.TypeAAAA, 300, "2001:db8:85a3:8d3:1319:8a2e:370:7344"))
						})

						By("second request", func() {
							Eventually(func(g Gomega) {
								resp, err = sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeAAAA)))
								g.Expect(err).Should(Succeed())
								g.Expect(resp.RType).Should(Equal(ResponseTypeCACHED))
								g.Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
								// still one call to upstream
								g.Expect(m.Calls).Should(HaveLen(1))
								// ttl is smaller
								g.Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.",
									dns.TypeAAAA, 299, "2001:db8:85a3:8d3:1319:8a2e:370:7344"))
							}, "500ms").Should(Succeed())

						})
					})
				})

			})

		})
		When("max caching time is defined", func() {

			BeforeEach(func() {
				mockAnswer, _ = util.NewMsgWithAnswer(
					"example.com.",
					1230,
					dns.Type(dns.TypeAAAA),
					"2001:0db8:85a3:08d3:1319:8a2e:0370:7344",
				)
			})
			Context("max caching time is negative -> caching is disabled", func() {
				BeforeEach(func() {
					sutConfig = config.CachingConfig{
						MaxCachingTime: config.Duration(time.Minute * -1),
					}
				})

				It("Shouldn't cache any responses", func() {
					By("first request", func() {
						resp, err = sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeAAAA)))
						Expect(err).Should(Succeed())
						Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
						Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
						Expect(m.Calls).Should(HaveLen(1))
						Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.",
							dns.TypeAAAA, 1230, "2001:db8:85a3:8d3:1319:8a2e:370:7344"))
					})

					By("second request", func() {
						Eventually(func(g Gomega) {
							resp, err = sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeAAAA)))
							g.Expect(err).Should(Succeed())
							g.Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
							g.Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
							//  one more call to upstream
							g.Expect(m.Calls).Should(HaveLen(2))
							g.Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.",
								dns.TypeAAAA, 1230, "2001:db8:85a3:8d3:1319:8a2e:370:7344"))
						}, "500ms").Should(Succeed())
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
						resp, err = sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeAAAA)))
						Expect(err).Should(Succeed())
						Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
						Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
						Expect(m.Calls).Should(HaveLen(1))
						Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.",
							dns.TypeAAAA, 240, "2001:db8:85a3:8d3:1319:8a2e:370:7344"))
					})

					By("second request", func() {
						Eventually(func(g Gomega) {
							resp, err = sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeAAAA)))
							g.Expect(err).Should(Succeed())
							g.Expect(resp.RType).Should(Equal(ResponseTypeCACHED))
							g.Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
							// still one call to upstream
							g.Expect(m.Calls).Should(HaveLen(1))
							// ttl is smaller
							g.Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.",
								dns.TypeAAAA, 239, "2001:db8:85a3:8d3:1319:8a2e:370:7344"))
						}, "1s").Should(Succeed())
					})
				})
			})
		})
		When("Entry expires in cache", func() {
			BeforeEach(func() {
				mockAnswer, _ = util.NewMsgWithAnswer("example.com.", 1, dns.Type(dns.TypeA), "1.1.1.1")
			})
			Context("max caching time is defined", func() {
				BeforeEach(func() {
					sutConfig = config.CachingConfig{
						MaxCachingTime: config.Duration(time.Minute * 1),
					}
				})
				It("should cache response and return 0 TTL if entry is expired", func() {
					By("first request", func() {
						resp, err = sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeA)))
						Expect(err).Should(Succeed())
						Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
						Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
						Expect(m.Calls).Should(HaveLen(1))
						Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.",
							dns.TypeA, 1, "1.1.1.1"))
					})

					By("second request", func() {
						Eventually(func(g Gomega) {
							resp, err = sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeA)))
							g.Expect(err).Should(Succeed())
							g.Expect(resp.RType).Should(Equal(ResponseTypeCACHED))
							g.Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
							// still one call to upstream
							g.Expect(m.Calls).Should(HaveLen(1))
							// ttl is 0
							g.Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.",
								dns.TypeA, 0, "1.1.1.1"))
						}, "1100ms").Should(Succeed())

					})
				})
			})
		})
	})

	Describe("Negative cache (caching if upstream resolver returns NXDOMAIN)", func() {
		Context("Caching if upstream resolver returns NXDOMAIN", func() {
			When("Upstream resolver returns NXDOMAIN with caching", func() {
				BeforeEach(func() {
					mockAnswer.Rcode = dns.RcodeNameError
				})

				It("response should be cached", func() {
					By("first request", func() {
						resp, err = sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeAAAA)))
						Expect(err).Should(Succeed())
						Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
						Expect(resp.Res.Rcode).Should(Equal(dns.RcodeNameError))
						Expect(m.Calls).Should(HaveLen(1))
					})

					By("second request", func() {
						Eventually(func(g Gomega) {
							resp, err = sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeAAAA)))
							g.Expect(err).Should(Succeed())
							g.Expect(resp.RType).Should(Equal(ResponseTypeCACHED))
							g.Expect(resp.Reason).Should(Equal("CACHED NEGATIVE"))
							g.Expect(resp.Res.Rcode).Should(Equal(dns.RcodeNameError))
							// still one call to resolver
							g.Expect(m.Calls).Should(HaveLen(1))
						}, "500ms").Should(Succeed())
					})
				})

			})
			When("Upstream resolver returns NXDOMAIN without caching", func() {
				BeforeEach(func() {
					mockAnswer.Rcode = dns.RcodeNameError
					sutConfig = config.CachingConfig{
						CacheTimeNegative: config.Duration(time.Minute * -1),
					}
				})

				It("response shouldn't be cached", func() {
					By("first request", func() {
						resp, err = sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeAAAA)))
						Expect(err).Should(Succeed())
						Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
						Expect(resp.Res.Rcode).Should(Equal(dns.RcodeNameError))
						Expect(m.Calls).Should(HaveLen(1))
					})

					By("second request", func() {
						Eventually(func(g Gomega) {
							resp, err = sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeAAAA)))
							g.Expect(err).Should(Succeed())
							g.Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
							g.Expect(resp.Res.Rcode).Should(Equal(dns.RcodeNameError))
							g.Expect(m.Calls).Should(HaveLen(2))
						}, "500ms").Should(Succeed())
					})
				})
			})
		})
		Context("Caching if upstream resolver returns empty result", func() {
			When("Upstream resolver returns empty result with caching", func() {
				BeforeEach(func() {
					mockAnswer.Rcode = dns.RcodeSuccess
					mockAnswer.Answer = make([]dns.RR, 0)
				})

				It("response should be cached", func() {
					By("first request", func() {
						resp, err = sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeAAAA)))
						Expect(err).Should(Succeed())
						Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
						Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
						Expect(m.Calls).Should(HaveLen(1))
					})

					By("second request", func() {
						Eventually(func(g Gomega) {
							resp, err = sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeAAAA)))
							g.Expect(err).Should(Succeed())
							g.Expect(resp.RType).Should(Equal(ResponseTypeCACHED))
							g.Expect(resp.Reason).Should(Equal("CACHED"))
							g.Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
							// still one call to resolver
							g.Expect(m.Calls).Should(HaveLen(1))
						}, "500ms").Should(Succeed())
					})
				})

			})
		})
	})

	Describe("Not A / AAAA queries should also be cached", func() {
		When("MX query will be performed", func() {
			BeforeEach(func() {
				mockAnswer, _ = util.NewMsgWithAnswer("google.de.", 180, dns.Type(dns.TypeMX), "10 alt1.aspmx.l.google.com.")
			})
			It("Should be cached", func() {
				By("first request", func() {
					resp, err = sut.Resolve(newRequest("google.de.", dns.Type(dns.TypeMX)))
					Expect(err).Should(Succeed())
					Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(m.Calls).Should(HaveLen(1))
					Expect(resp.Res.Answer).Should(BeDNSRecord("google.de.", dns.TypeMX, 180, "alt1.aspmx.l.google.com."))
				})

				By("second request", func() {
					Eventually(func(g Gomega) {
						resp, err = sut.Resolve(newRequest("google.de.", dns.Type(dns.TypeMX)))
						g.Expect(err).Should(Succeed())
						g.Expect(resp.RType).Should(Equal(ResponseTypeCACHED))
						g.Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
						g.Expect(m.Calls).Should(HaveLen(1))
						g.Expect(resp.Res.Answer).Should(BeDNSRecord("google.de.", dns.TypeMX, 179, "alt1.aspmx.l.google.com."))
					}, "1s").Should(Succeed())

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
				Expect(len(c)).Should(BeNumerically(">", 1))
			})
		})

		When("resolver is disabled", func() {
			BeforeEach(func() {
				sutConfig = config.CachingConfig{
					MaxCachingTime: config.Duration(time.Minute * -1),
				}
			})
			It("should return 'disabled'", func() {
				c := sut.Configuration()
				Expect(c).Should(ContainElement(configStatusDisabled))
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
				Expect(len(c)).Should(BeNumerically(">", 1))
				Expect(c).Should(ContainElement(ContainSubstring("prefetchThreshold")))
			})
		})
	})

	Describe("Redis is configured", func() {
		var (
			redisServer *miniredis.Miniredis
			redisClient *redis.Client
			redisConfig *config.RedisConfig
		)
		BeforeEach(func() {
			redisServer, err = miniredis.Run()

			Expect(err).Should(Succeed())

			var rcfg config.RedisConfig
			err = defaults.Set(&rcfg)

			Expect(err).Should(Succeed())

			rcfg.Address = redisServer.Addr()
			redisConfig = &rcfg
			redisClient, err = redis.New(redisConfig)

			Expect(err).Should(Succeed())
			Expect(redisClient).ShouldNot(BeNil())
		})
		AfterEach(func() {
			redisServer.Close()
		})
		When("cache", func() {
			JustBeforeEach(func() {
				sutConfig = config.CachingConfig{
					MaxCachingTime: config.Duration(time.Second * 10),
				}
				mockAnswer, _ = util.NewMsgWithAnswer("example.com.", 1000, dns.Type(dns.TypeA), "1.1.1.1")

				sut = NewCachingResolver(sutConfig, redisClient)
				m = &mockResolver{}
				m.On("Resolve", mock.Anything).Return(&Response{Res: mockAnswer}, nil)
				sut.Next(m)
			})

			It("put in redis", func() {
				resp, err = sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeA)))
				Expect(err).Should(Succeed())

				Eventually(func() []string {
					return redisServer.DB(redisConfig.Database).Keys()
				}, "50ms").Should(HaveLen(1))
			})

			It("load", func() {
				request := newRequest("example2.com.", dns.Type(dns.TypeA))
				domain := util.ExtractDomain(request.Req.Question[0])
				cacheKey := util.GenerateCacheKey(dns.Type(dns.TypeA), domain)
				redisMockMsg := &redis.CacheMessage{
					Key: cacheKey,
					Response: &Response{
						RType:  ResponseTypeCACHED,
						Reason: "MOCK_REDIS",
						Res:    mockAnswer,
					},
				}
				redisClient.CacheChannel <- redisMockMsg
				time.Sleep(time.Second)

				Eventually(func() error {
					resp, err = sut.Resolve(request)

					return err
				}, "50ms").Should(Succeed())
			})
		})
	})
})
