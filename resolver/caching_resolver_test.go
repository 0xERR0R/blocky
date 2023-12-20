package resolver

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/evt"
	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/log"
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
		sut        *CachingResolver
		sutConfig  config.Caching
		m          *mockResolver
		mockAnswer *dns.Msg
		ctx        context.Context
		cancelFn   context.CancelFunc
	)

	Describe("Type", func() {
		It("follows conventions", func() {
			expectValidResolverType(sut)
		})
	})

	BeforeEach(func() {
		sutConfig = config.Caching{}
		if err := defaults.Set(&sutConfig); err != nil {
			panic(err)
		}
		mockAnswer = new(dns.Msg)
	})

	JustBeforeEach(func() {
		ctx, cancelFn = context.WithCancel(context.Background())
		DeferCleanup(cancelFn)

		sut = NewCachingResolver(ctx, sutConfig, nil)
		m = &mockResolver{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: mockAnswer}, nil)
		sut.Next(m)
	})

	Describe("IsEnabled", func() {
		It("is true", func() {
			Expect(sut.IsEnabled()).Should(BeTrue())
		})

		When("max caching time is negative", func() {
			BeforeEach(func() {
				sutConfig = config.Caching{
					MaxCachingTime: config.Duration(time.Minute * -1),
				}
			})
			It("is false", func() {
				Expect(sut.IsEnabled()).Should(BeFalse())
			})
		})
	})

	Describe("LogConfig", func() {
		It("should log something", func() {
			logger, hook := log.NewMockEntry()

			sut.LogConfig(logger)

			Expect(hook.Calls).ShouldNot(BeEmpty())
		})
	})

	Describe("Caching responses", func() {
		When("prefetching is enabled", func() {
			BeforeEach(func() {
				sutConfig = config.Caching{
					Prefetching:       true,
					PrefetchExpires:   config.Duration(time.Minute * 120),
					PrefetchThreshold: 5,
				}
				mockAnswer, _ = util.NewMsgWithAnswer("example.com.", 2, A, "123.122.121.120")
			})

			It("should prefetch domain if query count > threshold", func() {
				// prepare resolver, set smaller caching times for testing
				prefetchThreshold := 5
				configureCaches(ctx, sut, &sutConfig)

				domainPrefetched := make(chan bool, 1)
				prefetchHitDomain := make(chan bool, 1)
				prefetchedCnt := make(chan int, 1)
				Expect(Bus().SubscribeOnce(CachingPrefetchCacheHit, func(domain string) {
					prefetchHitDomain <- true
				})).Should(Succeed())
				Expect(Bus().SubscribeOnce(CachingDomainPrefetched, func(domain string) {
					domainPrefetched <- true
				})).Should(Succeed())

				Expect(Bus().SubscribeOnce(CachingDomainsToPrefetchCountChanged, func(cnt int) {
					prefetchedCnt <- cnt
				})).Should(Succeed())

				// first request
				_, _ = sut.Resolve(ctx, newRequest("example.com.", A))

				// Domain is not prefetched
				Expect(domainPrefetched).ShouldNot(Receive())

				// Domain is in prefetched domain cache
				Expect(prefetchedCnt).Should(Receive(Equal(1)))

				// now query again > threshold
				for i := 0; i < prefetchThreshold+1; i++ {
					_, err := sut.Resolve(ctx, newRequest("example.com.", A))
					Expect(err).Should(Succeed())
				}

				// now is this domain prefetched
				Eventually(domainPrefetched, "10s").Should(Receive(Equal(true)))

				// and it should hit from prefetch cache
				Expect(sut.Resolve(ctx, newRequest("example.com.", A))).
					Should(
						SatisfyAll(
							HaveResponseType(ResponseTypeCACHED),
							HaveReturnCode(dns.RcodeSuccess),
							BeDNSRecord("example.com.", A, "123.122.121.120"),
							HaveTTL(BeNumerically("<=", 2))))
				Eventually(prefetchHitDomain, "10s").Should(Receive(Equal(true)))
			})
		})
		When("caching with default values is enabled", func() {
			BeforeEach(func() {
				rr1, err := dns.NewRR(fmt.Sprintf("%s\t%d\tIN\t%s\t%s", "example.com.", 600, A, "1.2.3.4"))
				Expect(err).Should(Succeed())

				rr2, err := dns.NewRR(fmt.Sprintf("%s\t%d\tIN\t%s\t%s", "example.com.", 950, CNAME, "cname.example.com"))
				Expect(err).Should(Succeed())

				msg := new(dns.Msg)
				msg.Answer = []dns.RR{rr1, rr2}
				mockAnswer = msg
			})
			It("should cache response and use response's TTL for multiple records", func() {
				By("first request", func() {
					result, err := sut.Resolve(ctx, newRequest("example.com.", A))
					Expect(err).Should(Succeed())
					Expect(result).
						Should(
							SatisfyAll(
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
								WithTransform(ToAnswer, SatisfyAll(
									HaveLen(2),
								)),
							))

					Expect(result.Res.Answer[0]).Should(HaveTTL(BeNumerically("==", 600)))
					Expect(result.Res.Answer[1]).Should(HaveTTL(BeNumerically("==", 950)))

					Expect(m.Calls).Should(HaveLen(1))
				})

				By("second request", func() {
					Eventually(func(g Gomega) {
						result, err := sut.Resolve(ctx, newRequest("example.com.", A))
						g.Expect(err).Should(Succeed())
						g.Expect(result).
							Should(
								SatisfyAll(
									HaveResponseType(ResponseTypeCACHED),
									HaveReturnCode(dns.RcodeSuccess),
									WithTransform(ToAnswer, SatisfyAll(
										HaveLen(2),
									))))

						g.Expect(result.Res.Answer[0]).Should(HaveTTL(BeNumerically("<=", 599)))
						g.Expect(result.Res.Answer[1]).Should(HaveTTL(BeNumerically("<=", 949)))

						// still one call to upstream
						g.Expect(m.Calls).Should(HaveLen(1))
					}, "1s").Should(Succeed())
				})
			})
		})
		When("min caching time is defined", func() {
			BeforeEach(func() {
				sutConfig = config.Caching{
					MinCachingTime: config.Duration(time.Minute * 5),
				}
			})
			Context("response TTL is bigger than defined min caching time", func() {
				BeforeEach(func() {
					mockAnswer, _ = util.NewMsgWithAnswer("example.com.", 600, A, "123.122.121.120")
				})

				It("should cache response and use response's TTL", func() {
					By("first request", func() {
						domain := make(chan bool, 1)
						_ = Bus().SubscribeOnce(CachingResultCacheMiss, func(d string) {
							domain <- true
						})

						totalCacheCount := make(chan int, 1)
						_ = Bus().SubscribeOnce(CachingResultCacheChanged, func(d int) {
							totalCacheCount <- d
						})
						Expect(sut.Resolve(ctx, newRequest("example.com.", A))).
							Should(
								SatisfyAll(
									HaveResponseType(ResponseTypeRESOLVED),
									HaveReturnCode(dns.RcodeSuccess),
									BeDNSRecord("example.com.", A, "123.122.121.120"),
									HaveTTL(BeNumerically("==", 600))))

						Expect(m.Calls).Should(HaveLen(1))

						Expect(domain).Should(Receive(Equal(true)))
						Expect(totalCacheCount).Should(Receive(Equal(1)))
					})

					By("second request", func() {
						Eventually(func(g Gomega) {
							domain := make(chan bool, 1)
							_ = Bus().SubscribeOnce(CachingResultCacheHit, func(d string) {
								domain <- true
							})

							g.Expect(sut.Resolve(ctx, newRequest("example.com.", A))).
								Should(
									SatisfyAll(
										HaveResponseType(ResponseTypeCACHED),
										HaveReturnCode(dns.RcodeSuccess),
										BeDNSRecord("example.com.", A, "123.122.121.120"),
										// ttl is smaller
										HaveTTL(BeNumerically("<=", 599))))

							// still one call to upstream
							g.Expect(m.Calls).Should(HaveLen(1))

							g.Expect(domain).Should(Receive(Equal(true)))
						}, "1s").Should(Succeed())
					})
				})
			})
			Context("response TTL is smaller than defined min caching time", func() {
				Context("A query", func() {
					BeforeEach(func() {
						mockAnswer, _ = util.NewMsgWithAnswer("example.com.", 123, A, "123.122.121.120")
					})

					It("should cache response and use min caching time as TTL", func() {
						By("first request", func() {
							Expect(sut.Resolve(ctx, newRequest("example.com.", A))).
								Should(
									SatisfyAll(
										HaveResponseType(ResponseTypeRESOLVED),
										HaveReturnCode(dns.RcodeSuccess),
										BeDNSRecord("example.com.", A, "123.122.121.120"),
										HaveTTL(BeNumerically("==", 300))))

							Expect(m.Calls).Should(HaveLen(1))
						})

						By("second request", func() {
							Eventually(sut.Resolve).
								WithContext(ctx).
								WithArguments(newRequest("example.com.", A)).
								Should(
									SatisfyAll(
										HaveResponseType(ResponseTypeCACHED),
										HaveReturnCode(dns.RcodeSuccess),
										BeDNSRecord("example.com.", A, "123.122.121.120"),
										// ttl is smaller
										HaveTTL(BeNumerically("<=", 299))))

							// still one call to upstream
							Expect(m.Calls).Should(HaveLen(1))
						})
					})
				})

				Context("AAAA query", func() {
					BeforeEach(func() {
						mockAnswer, _ = util.NewMsgWithAnswer("example.com.", 123,
							AAAA, "2001:0db8:85a3:08d3:1319:8a2e:0370:7344")
					})

					It("should cache response and use min caching time as TTL", func() {
						By("first request", func() {
							Expect(sut.Resolve(ctx, newRequest("example.com.", AAAA))).
								Should(
									SatisfyAll(
										HaveResponseType(ResponseTypeRESOLVED),
										HaveReturnCode(dns.RcodeSuccess),
										BeDNSRecord("example.com.", AAAA, "2001:db8:85a3:8d3:1319:8a2e:370:7344"),
										HaveTTL(BeNumerically("==", 300))))
							Expect(m.Calls).Should(HaveLen(1))
						})

						By("second request", func() {
							Eventually(sut.Resolve).
								WithContext(ctx).
								WithArguments(newRequest("example.com.", AAAA)).
								Should(
									SatisfyAll(
										HaveResponseType(ResponseTypeCACHED),
										HaveReturnCode(dns.RcodeSuccess),
										BeDNSRecord("example.com.", AAAA, "2001:db8:85a3:8d3:1319:8a2e:370:7344"),
										// ttl is smaller
										HaveTTL(BeNumerically("<=", 299))))

							// still one call to upstream
							Expect(m.Calls).Should(HaveLen(1))
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
					AAAA,
					"2001:0db8:85a3:08d3:1319:8a2e:0370:7344",
				)
			})
			Context("max caching time is negative -> caching is disabled", func() {
				BeforeEach(func() {
					sutConfig = config.Caching{
						MaxCachingTime: config.Duration(time.Minute * -1),
					}
				})

				It("Shouldn't cache any responses", func() {
					By("first request", func() {
						Expect(sut.Resolve(ctx, newRequest("example.com.", AAAA))).
							Should(
								SatisfyAll(
									HaveResponseType(ResponseTypeRESOLVED),
									HaveReturnCode(dns.RcodeSuccess),
									BeDNSRecord("example.com.", AAAA, "2001:db8:85a3:8d3:1319:8a2e:370:7344"),
									HaveTTL(BeNumerically("==", 1230))))
						Expect(m.Calls).Should(HaveLen(1))
					})

					By("second request", func() {
						Eventually(sut.Resolve).
							WithContext(ctx).
							WithArguments(newRequest("example.com.", AAAA)).
							Should(
								SatisfyAll(
									HaveResponseType(ResponseTypeRESOLVED),
									HaveReturnCode(dns.RcodeSuccess),
									BeDNSRecord("example.com.", AAAA, "2001:db8:85a3:8d3:1319:8a2e:370:7344"),
									// ttl is smaller
									HaveTTL(BeNumerically("==", 1230))))

						//  one more call to upstream
						Expect(m.Calls).Should(HaveLen(2))
					})
				})
			})

			Context("max caching time is positive", func() {
				BeforeEach(func() {
					sutConfig = config.Caching{
						MaxCachingTime: config.Duration(time.Minute * 4),
					}
				})
				It("should cache response and use max caching time as TTL if response TTL is bigger", func() {
					By("first request", func() {
						Expect(sut.Resolve(ctx, newRequest("example.com.", AAAA))).
							Should(
								SatisfyAll(
									HaveResponseType(ResponseTypeRESOLVED),
									HaveReturnCode(dns.RcodeSuccess),
									BeDNSRecord("example.com.",
										AAAA, "2001:db8:85a3:8d3:1319:8a2e:370:7344"),
									HaveTTL(BeNumerically("==", 240))))
					})

					By("second request", func() {
						Eventually(sut.Resolve).
							WithContext(ctx).
							WithArguments(newRequest("example.com.", AAAA)).
							Should(
								SatisfyAll(
									HaveResponseType(ResponseTypeCACHED),
									HaveReturnCode(dns.RcodeSuccess),
									BeDNSRecord("example.com.",
										AAAA, "2001:db8:85a3:8d3:1319:8a2e:370:7344"),
									// ttl is smaller
									HaveTTL(BeNumerically("<=", 239))))

						// still one call to upstream
						Expect(m.Calls).Should(HaveLen(1))
					})
				})
			})
		})
		When("Entry expires in cache", func() {
			BeforeEach(func() {
				mockAnswer, _ = util.NewMsgWithAnswer("example.com.", 1, A, "1.1.1.1")
			})
			Context("max caching time is defined", func() {
				BeforeEach(func() {
					sutConfig = config.Caching{
						MaxCachingTime: config.Duration(time.Minute * 1),
					}
				})
				It("should cache response and return 0 TTL if entry is expired", func() {
					By("first request", func() {
						Expect(sut.Resolve(ctx, newRequest("example.com.", A))).
							Should(
								SatisfyAll(
									HaveResponseType(ResponseTypeRESOLVED),
									HaveReturnCode(dns.RcodeSuccess),
									BeDNSRecord("example.com.",
										A, "1.1.1.1"),
									HaveTTL(BeNumerically("==", 1))))

						Expect(m.Calls).Should(HaveLen(1))
					})

					By("second request", func() {
						Eventually(sut.Resolve, "2s").
							WithContext(ctx).
							WithArguments(newRequest("example.com.", A)).
							Should(
								SatisfyAll(
									HaveResponseType(ResponseTypeCACHED),
									HaveReturnCode(dns.RcodeSuccess),
									BeDNSRecord("example.com.",
										A, "1.1.1.1"),
									// ttl is 0
									HaveTTL(BeNumerically("==", 0))))

						// still one call to upstream
						Expect(m.Calls).Should(HaveLen(1))
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
					By("default config should enable negative caching", func() {
						Expect(sutConfig.CacheTimeNegative).Should(BeNumerically(">", 0))
					})

					By("first request", func() {
						Expect(sut.Resolve(ctx, newRequest("example.com.", AAAA))).
							Should(SatisfyAll(
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeNameError),
								HaveNoAnswer(),
							))

						Expect(m.Calls).Should(HaveLen(1))
					})

					By("second request", func() {
						Eventually(sut.Resolve).
							WithContext(ctx).
							WithArguments(newRequest("example.com.", AAAA)).
							Should(SatisfyAll(
								HaveResponseType(ResponseTypeCACHED),
								HaveReason("CACHED NEGATIVE"),
								HaveReturnCode(dns.RcodeNameError),
								HaveNoAnswer(),
							))

						// still one call to resolver
						Expect(m.Calls).Should(HaveLen(1))
					})
				})
			})
			When("Upstream resolver returns NXDOMAIN without caching", func() {
				BeforeEach(func() {
					mockAnswer.Rcode = dns.RcodeNameError
					sutConfig = config.Caching{
						CacheTimeNegative: config.Duration(time.Minute * -1),
					}
				})

				It("response shouldn't be cached", func() {
					By("first request", func() {
						Expect(sut.Resolve(ctx, newRequest("example.com.", AAAA))).
							Should(SatisfyAll(
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeNameError),
								HaveNoAnswer(),
							))

						Expect(m.Calls).Should(HaveLen(1))
					})

					By("second request", func() {
						Eventually(sut.Resolve).
							WithContext(ctx).
							WithArguments(newRequest("example.com.", AAAA)).
							Should(SatisfyAll(
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReason(""),
								HaveReturnCode(dns.RcodeNameError),
								HaveNoAnswer(),
							))

						// one more call to upstream
						Expect(m.Calls).Should(HaveLen(2))
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
						Expect(sut.Resolve(ctx, newRequest("example.com.", AAAA))).
							Should(SatisfyAll(
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
								HaveNoAnswer(),
							))

						Expect(m.Calls).Should(HaveLen(1))
					})

					By("second request", func() {
						Eventually(sut.Resolve).
							WithContext(ctx).
							WithArguments(newRequest("example.com.", AAAA)).
							Should(SatisfyAll(
								HaveResponseType(ResponseTypeCACHED),
								HaveReason("CACHED"),
								HaveReturnCode(dns.RcodeSuccess),
								HaveNoAnswer(),
							))

						// still one call to resolver
						Expect(m.Calls).Should(HaveLen(1))
					})
				})
			})
		})
	})

	Describe("Not A / AAAA queries should also be cached", func() {
		When("MX query will be performed", func() {
			BeforeEach(func() {
				mockAnswer, _ = util.NewMsgWithAnswer("google.de.", 180, MX, "10 alt1.aspmx.l.google.com.")
			})
			It("Should be cached", func() {
				By("first request", func() {
					Expect(sut.Resolve(ctx, newRequest("google.de.", MX))).
						Should(SatisfyAll(
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
							BeDNSRecord("google.de.", MX, "alt1.aspmx.l.google.com."),
							HaveTTL(BeNumerically("==", 180)),
						))

					Expect(m.Calls).Should(HaveLen(1))
				})

				By("second request", func() {
					Eventually(sut.Resolve).
						WithContext(ctx).
						WithArguments(newRequest("google.de.", MX)).
						Should(SatisfyAll(
							HaveResponseType(ResponseTypeCACHED),
							HaveReason("CACHED"),
							HaveReturnCode(dns.RcodeSuccess),
							BeDNSRecord("google.de.", MX, "alt1.aspmx.l.google.com."),
							HaveTTL(BeNumerically("<=", 179)),
						))

					// still one call to resolver
					Expect(m.Calls).Should(HaveLen(1))
				})
			})
		})
	})

	Describe("Truncated responses should not be cached", func() {
		When("Some query returns truncated response", func() {
			BeforeEach(func() {
				mockAnswer, _ = util.NewMsgWithAnswer("google.de.", 180, A, "1.1.1.1")
				mockAnswer.Truncated = true
			})
			It("Should not be cached", func() {
				By("first request", func() {
					Expect(sut.Resolve(ctx, newRequest("google.de.", A))).
						Should(SatisfyAll(
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
							BeDNSRecord("google.de.", A, "1.1.1.1"),
							HaveTTL(BeNumerically("==", 180)),
						))

					Expect(m.Calls).Should(HaveLen(1))
				})

				By("second request", func() {
					Expect(sut.Resolve(ctx, newRequest("google.de.", A))).
						Should(SatisfyAll(
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
							BeDNSRecord("google.de.", A, "1.1.1.1"),
							HaveTTL(BeNumerically("==", 180)),
						))

					Expect(m.Calls).Should(HaveLen(2))
				})
			})
		})
	})

	Describe("Responses with CD flag should not be cached", func() {
		When("Some query returns response with CD flag", func() {
			BeforeEach(func() {
				mockAnswer, _ = util.NewMsgWithAnswer("google.de.", 180, A, "1.1.1.1")
				mockAnswer.CheckingDisabled = true
			})
			It("Should not be cached", func() {
				By("first request", func() {
					Expect(sut.Resolve(ctx, newRequest("google.de.", A))).
						Should(SatisfyAll(
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
							BeDNSRecord("google.de.", A, "1.1.1.1"),
							HaveTTL(BeNumerically("==", 180)),
						))

					Expect(m.Calls).Should(HaveLen(1))
				})

				By("second request", func() {
					Expect(sut.Resolve(ctx, newRequest("google.de.", A))).
						Should(SatisfyAll(
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
							BeDNSRecord("google.de.", A, "1.1.1.1"),
							HaveTTL(BeNumerically("==", 180)),
						))

					Expect(m.Calls).Should(HaveLen(2))
				})
			})
		})
	})

	Describe("EDNS pseudo records should not be cached", func() {
		When("Some query returns EDNS OPT RRs", func() {
			BeforeEach(func() {
				mockAnswer, _ = util.NewMsgWithAnswer("google.de.", 180, A, "1.1.1.1")
				opt := new(dns.OPT)
				opt.Hdr.Name = "."
				opt.Hdr.Rrtype = dns.TypeOPT
				opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "someclientcookie"})
				mockAnswer.Extra = append(mockAnswer.Extra, opt)
			})
			It("Should not be cached", func() {
				By("first request", func() {
					Expect(sut.Resolve(ctx, newRequest("google.de.", A))).
						Should(SatisfyAll(
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
							BeDNSRecord("google.de.", A, "1.1.1.1"),
							HaveTTL(BeNumerically("==", 180)),
							// original response has one ENDS0 Opt
							WithTransform(ToExtra,
								SatisfyAll(
									HaveLen(1),
								)),
						))

					Expect(m.Calls).Should(HaveLen(1))
				})

				By("second request", func() {
					Eventually(sut.Resolve).
						WithContext(ctx).
						WithArguments(newRequest("google.de.", A)).
						Should(SatisfyAll(
							HaveResponseType(ResponseTypeCACHED),
							HaveReason("CACHED"),
							HaveReturnCode(dns.RcodeSuccess),
							BeDNSRecord("google.de.", A, "1.1.1.1"),
							HaveTTL(BeNumerically("<=", 179)),
							// cached response is without EDNS RRs
							WithTransform(ToExtra,
								SatisfyAll(
									BeEmpty(),
								)),
						))

					// still one call to resolver
					Expect(m.Calls).Should(HaveLen(1))
				})
			})
		})
	})

	Describe("Redis is configured", func() {
		var (
			redisServer *miniredis.Miniredis
			redisClient *redis.Client
			redisConfig *config.Redis
			err         error
		)
		BeforeEach(func() {
			redisServer, err = miniredis.Run()

			Expect(err).Should(Succeed())

			var rcfg config.Redis
			err = defaults.Set(&rcfg)

			Expect(err).Should(Succeed())

			rcfg.Address = redisServer.Addr()
			redisConfig = &rcfg
			redisClient, err = redis.New(context.TODO(), redisConfig)

			Expect(err).Should(Succeed())
			Expect(redisClient).ShouldNot(BeNil())
		})
		AfterEach(func() {
			redisServer.Close()
		})
		When("cache", func() {
			JustBeforeEach(func() {
				sutConfig = config.Caching{
					MaxCachingTime: config.Duration(time.Second * 10),
				}
				mockAnswer, _ = util.NewMsgWithAnswer("example.com.", 1000, A, "1.1.1.1")

				sut = NewCachingResolver(ctx, sutConfig, redisClient)
				m = &mockResolver{}
				m.On("Resolve", mock.Anything).Return(&Response{Res: mockAnswer}, nil)
				sut.Next(m)
			})

			It("put in redis", func() {
				Expect(sut.Resolve(ctx, newRequest("example.com.", A))).
					Should(HaveResponseType(ResponseTypeRESOLVED))

				Eventually(func() []string {
					return redisServer.DB(redisConfig.Database).Keys()
				}).Should(HaveLen(1))
			})

			It("load", func() {
				request := newRequest("example2.com.", A)
				domain := util.ExtractDomain(request.Req.Question[0])
				cacheKey := util.GenerateCacheKey(A, domain)
				redisMockMsg := &redis.CacheMessage{
					Key: cacheKey,
					Response: &Response{
						RType:  ResponseTypeCACHED,
						Reason: "MOCK_REDIS",
						Res:    mockAnswer,
					},
				}
				redisClient.CacheChannel <- redisMockMsg

				Eventually(sut.Resolve).
					WithContext(ctx).
					WithArguments(request).
					Should(
						SatisfyAll(
							HaveResponseType(ResponseTypeCACHED),
							HaveTTL(BeNumerically("<=", 10)),
						))
			})
		})
	})
	Context("isRequestCacheable", func() {
		var request *Request
		When("request is not cacheable", func() {
			BeforeEach(func() {
				request = newRequest("example.com.", A)
				e := new(dns.EDNS0_SUBNET)
				e.SourceScope = 0
				e.Address = net.ParseIP("192.168.0.0")
				e.Family = 1
				e.SourceNetmask = 24
				util.SetEdns0Option(request.Req, e)
			})

			It("should return false", func() {
				Expect(isRequestCacheable(request)).
					Should(BeFalse())
			})
		})
		When("request is cacheable", func() {
			BeforeEach(func() {
				request = newRequest("example.com.", A)
				e := new(dns.EDNS0_SUBNET)
				e.SourceScope = 0
				e.Address = net.ParseIP("192.168.0.10")
				e.Family = 1
				e.SourceNetmask = 32
				util.SetEdns0Option(request.Req, e)
			})

			It("should return true", func() {
				Expect(isRequestCacheable(request)).
					Should(BeTrue())
			})
		})
	})
})
