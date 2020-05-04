package resolver

import (
	"blocky/config"
	. "blocky/helpertest"
	"blocky/util"

	"time"

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
		When("min caching time is defined", func() {
			BeforeEach(func() {
				sutConfig = config.CachingConfig{
					MinCachingTime: 5,
				}
			})
			Context("response TTL is bigger than defined min caching time", func() {
				BeforeEach(func() {
					mockAnswer, _ = util.NewMsgWithAnswer("example.com.", 600, dns.TypeA, "123.122.121.120")
				})

				It("should cache response and use response's TTL", func() {

					By("first request", func() {
						resp, err = sut.Resolve(newRequest("example.com.", dns.TypeA))
						Expect(err).Should(Succeed())
						Expect(resp.RType).Should(Equal(RESOLVED))
						Expect(m.Calls).Should(HaveLen(1))
						Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
						Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 600, "123.122.121.120"))
					})

					time.Sleep(500 * time.Millisecond)

					By("second request", func() {
						resp, err = sut.Resolve(newRequest("example.com.", dns.TypeA))
						Expect(err).Should(Succeed())
						Expect(resp.RType).Should(Equal(CACHED))
						// still one call to upstream
						Expect(m.Calls).Should(HaveLen(1))
						Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
						// ttl is smaller
						Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 599, "123.122.121.120"))
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
							Expect(resp.RType).Should(Equal(RESOLVED))
							Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
							Expect(m.Calls).Should(HaveLen(1))
							Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 300, "123.122.121.120"))
						})

						time.Sleep(500 * time.Millisecond)

						By("second request", func() {
							resp, err = sut.Resolve(newRequest("example.com.", dns.TypeA))
							Expect(err).Should(Succeed())
							Expect(resp.RType).Should(Equal(CACHED))
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
							Expect(resp.RType).Should(Equal(RESOLVED))
							Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
							Expect(m.Calls).Should(HaveLen(1))
							Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.",
								dns.TypeAAAA, 300, "2001:db8:85a3:8d3:1319:8a2e:370:7344"))
						})

						time.Sleep(500 * time.Millisecond)

						By("second request", func() {
							resp, err = sut.Resolve(newRequest("example.com.", dns.TypeAAAA))
							Expect(err).Should(Succeed())
							Expect(resp.RType).Should(Equal(CACHED))
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
						MaxCachingTime: -1,
					}
				})

				It("Shouldn't cache any responses", func() {
					By("first request", func() {
						resp, err = sut.Resolve(newRequest("example.com.", dns.TypeAAAA))
						Expect(err).Should(Succeed())
						Expect(resp.RType).Should(Equal(RESOLVED))
						Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
						Expect(m.Calls).Should(HaveLen(1))
						Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.",
							dns.TypeAAAA, 1230, "2001:db8:85a3:8d3:1319:8a2e:370:7344"))
					})

					time.Sleep(500 * time.Millisecond)

					By("second request", func() {
						resp, err = sut.Resolve(newRequest("example.com.", dns.TypeAAAA))
						Expect(err).Should(Succeed())
						Expect(resp.RType).Should(Equal(RESOLVED))
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
						MaxCachingTime: 4,
					}
				})
				It("should cache response and use max caching time as TTL if response TTL is bigger", func() {
					By("first request", func() {
						resp, err = sut.Resolve(newRequest("example.com.", dns.TypeAAAA))
						Expect(err).Should(Succeed())
						Expect(resp.RType).Should(Equal(RESOLVED))
						Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
						Expect(m.Calls).Should(HaveLen(1))
						Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.",
							dns.TypeAAAA, 240, "2001:db8:85a3:8d3:1319:8a2e:370:7344"))
					})

					time.Sleep(500 * time.Millisecond)

					By("second request", func() {
						resp, err = sut.Resolve(newRequest("example.com.", dns.TypeAAAA))
						Expect(err).Should(Succeed())
						Expect(resp.RType).Should(Equal(CACHED))
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
					Expect(resp.RType).Should(Equal(RESOLVED))
					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeNameError))
					Expect(m.Calls).Should(HaveLen(1))
				})

				time.Sleep(500 * time.Millisecond)

				By("second request", func() {
					resp, err = sut.Resolve(newRequest("example.com.", dns.TypeAAAA))
					Expect(err).Should(Succeed())
					Expect(resp.RType).Should(Equal(CACHED))
					Expect(resp.Reason).Should(Equal("CACHED NEGATIVE"))
					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeNameError))
					// still one call to resolver
					Expect(m.Calls).Should(HaveLen(1))
				})
			})

		})
	})

	Describe("Not A / AAAA queries should not be cached", func() {
		When("MX query will be performed", func() {
			BeforeEach(func() {
				mockAnswer, _ = util.NewMsgWithAnswer("google.de.", 180, dns.TypeMX, "10 alt1.aspmx.l.google.com.")
			})
			It("Shouldn't be cached", func() {
				By("first request", func() {
					resp, err = sut.Resolve(newRequest("google.de.", dns.TypeMX))
					Expect(err).Should(Succeed())
					Expect(resp.RType).Should(Equal(RESOLVED))
					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(m.Calls).Should(HaveLen(1))
					Expect(resp.Res.Answer).Should(BeDNSRecord("google.de.", dns.TypeMX, 180, "alt1.aspmx.l.google.com."))
				})

				By("second request", func() {
					resp, err = sut.Resolve(newRequest("google.de.", dns.TypeMX))
					Expect(err).Should(Succeed())
					Expect(resp.RType).Should(Equal(RESOLVED))
					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					Expect(m.Calls).Should(HaveLen(2))
					Expect(resp.Res.Answer).Should(BeDNSRecord("google.de.", dns.TypeMX, 180, "alt1.aspmx.l.google.com."))
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
					MaxCachingTime: -1,
				}
			})
			It("should return 'disabled''", func() {
				c := sut.Configuration()
				Expect(c).Should(HaveLen(1))
				Expect(c).Should(Equal([]string{"deactivated"}))
			})
		})
	})
})
