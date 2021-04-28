package resolver

import (
	"blocky/config"
	. "blocky/evt"
	. "blocky/helpertest"
	"blocky/lists"
	. "blocky/log"
	"blocky/util"

	"os"
	"time"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("BlockingResolver", func() {
	var (
		sut        *BlockingResolver
		sutConfig  config.BlockingConfig
		m          *resolverMock
		mockAnswer *dns.Msg

		err  error
		resp *Response

		group1File, group2File, defaultGroupFile *os.File

		expectedReturnCode int
	)

	BeforeSuite(func() {
		group1File = TempFile("DOMAIN1.com")
		group2File = TempFile("blocked2.com")
		defaultGroupFile = TempFile(
			`blocked3.com
123.145.123.145
2001:db8:85a3:08d3::370:7344
badcnamedomain.com`)
	})

	AfterSuite(func() {
		_ = group1File.Close()
		_ = group2File.Close()
		_ = defaultGroupFile.Close()
	})

	BeforeEach(func() {
		expectedReturnCode = dns.RcodeSuccess

		sutConfig = config.BlockingConfig{}

		mockAnswer = new(dns.Msg)
	})

	JustBeforeEach(func() {
		m = &resolverMock{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: mockAnswer}, nil)
		sut = NewBlockingResolver(sutConfig).(*BlockingResolver)
		sut.Next(m)
		sut.RefreshLists()
	})

	AfterEach(func() {
		Expect(err).Should(Succeed())
		if resp != nil {
			Expect(resp.Res.Rcode).Should(Equal(expectedReturnCode))
		}
	})

	Describe("Events", func() {
		BeforeEach(func() {
			sutConfig = config.BlockingConfig{
				BlackLists: map[string][]string{
					"gr1": {group1File.Name()},
					"gr2": {group2File.Name()},
				},
			}
		})
		When("List is refreshed", func() {
			It("event should be fired", func() {
				groupCnt := make(map[string]int)
				err = Bus().Subscribe(BlockingCacheGroupChanged, func(listType lists.ListCacheType, group string, cnt int) {
					groupCnt[group] = cnt
				})
				Expect(err).Should(Succeed())

				// recreate to trigger a reload
				sut = NewBlockingResolver(sutConfig).(*BlockingResolver)

				time.Sleep(time.Second)

				Expect(groupCnt).Should(HaveLen(2))

			})
		})
	})

	Describe("Blocking requests", func() {
		var rType ResponseType
		BeforeEach(func() {
			sutConfig = config.BlockingConfig{
				BlackLists: map[string][]string{
					"gr1":          {group1File.Name()},
					"gr2":          {group2File.Name()},
					"defaultGroup": {defaultGroupFile.Name()},
				},
				ClientGroupsBlock: map[string][]string{
					"client1":        {"gr1"},
					"192.168.178.55": {"gr1"},
					"altName":        {"gr2"},
					"10.43.8.67/28":  {"gr1"},
					"wildcard[0-9]*": {"gr1"},
					"default":        {"defaultGroup"},
				},
				BlockType: "ZeroIP",
			}
			rType = BLOCKED
		})
		AfterEach(func() {
			Expect(resp.RType).Should(Equal(rType))
		})

		When("client name is defined in client groups block", func() {
			It("should block the A query if domain is on the black list", func() {
				resp, err = sut.Resolve(newRequestWithClient("domain1.com.", dns.TypeA, "1.2.1.2", "client1"))

				Expect(resp.Res.Answer).Should(BeDNSRecord("domain1.com.", dns.TypeA, 21600, "0.0.0.0"))
			})
			It("should block the AAAA query if domain is on the black list", func() {
				resp, err = sut.Resolve(newRequestWithClient("domain1.com.", dns.TypeAAAA, "1.2.1.2", "client1"))

				Expect(resp.Res.Answer).Should(BeDNSRecord("domain1.com.", dns.TypeAAAA, 21600, "::"))
			})
			It("should block the HTTPS query if domain is on the black list", func() {
				resp, err = sut.Resolve(newRequestWithClient("domain1.com.", dns.TypeHTTPS, "1.2.1.2", "client1"))

				expectedReturnCode = dns.RcodeNameError
				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeNameError))
			})
			It("should block the MX query if domain is on the black list", func() {
				resp, err = sut.Resolve(newRequestWithClient("domain1.com.", dns.TypeMX, "1.2.1.2", "client1"))

				expectedReturnCode = dns.RcodeNameError
				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeNameError))
			})
		})

		When("Client ip is defined in client groups block", func() {
			It("should block the query if domain is on the black list", func() {
				resp, err = sut.Resolve(newRequestWithClient("domain1.com.", dns.TypeA, "192.168.178.55", "unknown"))

				Expect(resp.Res.Answer).Should(BeDNSRecord("domain1.com.", dns.TypeA, 21600, "0.0.0.0"))
			})
		})
		When("Client CIDR (10.43.8.64 - 10.43.8.79) is defined in client groups block", func() {
			JustBeforeEach(func() {
				rType = RESOLVED
			})
			It("should not block the query for 10.43.8.63 if domain is on the black list", func() {

				resp, err = sut.Resolve(newRequestWithClient("domain1.com.", dns.TypeA, "10.43.8.63", "unknown"))

				// was delegated to next resolver
				m.AssertExpectations(GinkgoT())
			})
			It("should not block the query for 10.43.8.80 if domain is on the black list", func() {
				resp, err = sut.Resolve(newRequestWithClient("domain1.com.", dns.TypeA, "10.43.8.80", "unknown"))

				// was delegated to next resolver
				m.AssertExpectations(GinkgoT())
			})
		})

		When("Client CIDR (10.43.8.64 - 10.43.8.79) is defined in client groups block", func() {

			It("should block the query for 10.43.8.64 if domain is on the black list", func() {
				resp, err = sut.Resolve(newRequestWithClient("domain1.com.", dns.TypeA, "10.43.8.64", "unknown"))

				Expect(resp.Res.Answer).Should(BeDNSRecord("domain1.com.", dns.TypeA, 21600, "0.0.0.0"))
			})
			It("should block the query for 10.43.8.79 if domain is on the black list", func() {
				resp, err = sut.Resolve(newRequestWithClient("domain1.com.", dns.TypeA, "10.43.8.79", "unknown"))

				Expect(resp.Res.Answer).Should(BeDNSRecord("domain1.com.", dns.TypeA, 21600, "0.0.0.0"))
			})
		})

		When("Client has multiple names and for each name a client group block definition exists", func() {
			It("should block query if domain is in one group", func() {
				resp, err = sut.Resolve(newRequestWithClient("domain1.com.", dns.TypeA, "1.2.1.2", "client1", "altName"))

				Expect(resp.Reason).Should(Equal("BLOCKED (gr1)"))
				Expect(resp.Res.Answer).Should(BeDNSRecord("domain1.com.", dns.TypeA, 21600, "0.0.0.0"))
			})
			It("should block query if domain is in another group too", func() {
				resp, err = sut.Resolve(newRequestWithClient("blocked2.com.", dns.TypeA, "1.2.1.2", "client1", "altName"))

				Expect(resp.Reason).Should(Equal("BLOCKED (gr2)"))
				Expect(resp.Res.Answer).Should(BeDNSRecord("blocked2.com.", dns.TypeA, 21600, "0.0.0.0"))
			})
		})
		When("Client name matches wildcard", func() {
			It("should block query if domain is in one group", func() {
				resp, err = sut.Resolve(newRequestWithClient("domain1.com.", dns.TypeA, "1.2.1.2", "wildcard1name"))

				Expect(resp.Reason).Should(Equal("BLOCKED (gr1)"))
				Expect(resp.Res.Answer).Should(BeDNSRecord("domain1.com.", dns.TypeA, 21600, "0.0.0.0"))
			})
		})

		When("Default group is defined", func() {
			It("should block domains from default group for each client", func() {
				resp, err = sut.Resolve(newRequestWithClient("blocked3.com.", dns.TypeA, "1.2.1.2", "unknown"))

				Expect(resp.Reason).Should(Equal("BLOCKED (defaultGroup)"))
				Expect(resp.Res.Answer).Should(BeDNSRecord("blocked3.com.", dns.TypeA, 21600, "0.0.0.0"))
			})
		})

		When("BlockType is NxDomain", func() {
			BeforeEach(func() {
				sutConfig = config.BlockingConfig{
					BlackLists: map[string][]string{
						"defaultGroup": {defaultGroupFile.Name()},
					},
					ClientGroupsBlock: map[string][]string{
						"default": {"defaultGroup"},
					},
					BlockType: "NxDomain",
				}
			})
			JustBeforeEach(func() {
				expectedReturnCode = dns.RcodeNameError
			})

			It("should return NXDOMAIN if query is blocked", func() {
				resp, err = sut.Resolve(newRequestWithClient("blocked3.com.", dns.TypeA, "1.2.1.2", "unknown"))

				Expect(resp.Reason).Should(Equal("BLOCKED (defaultGroup)"))
				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeNameError))
			})
		})

		When("BlockType is custom IP", func() {
			BeforeEach(func() {
				sutConfig = config.BlockingConfig{
					BlackLists: map[string][]string{
						"defaultGroup": {defaultGroupFile.Name()},
					},
					ClientGroupsBlock: map[string][]string{
						"default": {"defaultGroup"},
					},
					BlockType: "12.12.12.12, 2001:0db8:85a3:0000:0000:8a2e:0370:7334",
				}
			})

			It("should return ipv4 address for A query if query is blocked", func() {
				resp, err = sut.Resolve(newRequestWithClient("blocked3.com.", dns.TypeA, "1.2.1.2", "unknown"))

				Expect(resp.Reason).Should(Equal("BLOCKED (defaultGroup)"))
				Expect(resp.Res.Answer).Should(BeDNSRecord("blocked3.com.", dns.TypeA, 21600, "12.12.12.12"))
			})

			It("should return ipv6 address for AAAA query if query is blocked", func() {
				resp, err = sut.Resolve(newRequestWithClient("blocked3.com.", dns.TypeAAAA, "1.2.1.2", "unknown"))

				Expect(resp.Reason).Should(Equal("BLOCKED (defaultGroup)"))
				Expect(resp.Res.Answer).Should(BeDNSRecord("blocked3.com.", dns.TypeAAAA, 21600, "2001:db8:85a3::8a2e:370:7334"))
			})
		})

		When("BlockType is custom IP only for ipv4", func() {
			BeforeEach(func() {
				sutConfig = config.BlockingConfig{
					BlackLists: map[string][]string{
						"defaultGroup": {defaultGroupFile.Name()},
					},
					ClientGroupsBlock: map[string][]string{
						"default": {"defaultGroup"},
					},
					BlockType: "12.12.12.12",
				}
			})

			It("should use fallback for ipv6 and return zero ip", func() {
				resp, err = sut.Resolve(newRequestWithClient("blocked3.com.", dns.TypeAAAA, "1.2.1.2", "unknown"))

				Expect(resp.Reason).Should(Equal("BLOCKED (defaultGroup)"))
				Expect(resp.Res.Answer).Should(BeDNSRecord("blocked3.com.", dns.TypeAAAA, 21600, "::"))
			})

		})

		When("Blacklist contains IP", func() {
			When("IP4", func() {
				BeforeEach(func() {
					// return defined IP as response
					mockAnswer, _ = util.NewMsgWithAnswer("example.com.", 300, dns.TypeA, "123.145.123.145")
				})
				It("should block query, if lookup result contains blacklisted IP", func() {
					resp, err = sut.Resolve(newRequestWithClient("example.com.", dns.TypeA, "1.2.1.2", "unknown"))
					Expect(resp.Reason).Should(Equal("BLOCKED IP (defaultGroup)"))
					Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 21600, "0.0.0.0"))
				})
			})
			When("IP6", func() {
				BeforeEach(func() {
					// return defined IP as response
					mockAnswer, _ = util.NewMsgWithAnswer("example.com.", 300, dns.TypeAAAA, "2001:0db8:85a3:08d3::0370:7344")
				})
				It("should block query, if lookup result contains blacklisted IP", func() {
					resp, err = sut.Resolve(newRequestWithClient("example.com.", dns.TypeAAAA, "1.2.1.2", "unknown"))
					Expect(resp.Reason).Should(Equal("BLOCKED IP (defaultGroup)"))
					Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeAAAA, 21600, "::"))
				})
			})
		})

		When("blacklist contains domain which is CNAME in response", func() {
			BeforeEach(func() {
				// reconfigure mock, to return CNAMEs
				rr1, _ := dns.NewRR("example.com 300 IN CNAME domain.com")
				rr2, _ := dns.NewRR("domain.com 300 IN CNAME badcnamedomain.com")
				rr3, _ := dns.NewRR("badcnamedomain.com 300 IN A 125.125.125.125")
				mockAnswer = new(dns.Msg)
				mockAnswer.Answer = []dns.RR{rr1, rr2, rr3}
			})
			It("should block the query, if response contains a CNAME with domain on a blacklist", func() {
				resp, err = sut.Resolve(newRequestWithClient("example.com.", dns.TypeA, "1.2.1.2", "unknown"))
				Expect(resp.Reason).Should(Equal("BLOCKED CNAME (defaultGroup)"))
				Expect(resp.Res.Answer).Should(BeDNSRecord("example.com.", dns.TypeA, 21600, "0.0.0.0"))
			})
		})
	})

	Describe("Whitelisting", func() {
		When("Requested domain is on black and white list", func() {
			BeforeEach(func() {
				sutConfig = config.BlockingConfig{
					BlackLists: map[string][]string{"gr1": {group1File.Name()}},
					WhiteLists: map[string][]string{"gr1": {group1File.Name()}},
					ClientGroupsBlock: map[string][]string{
						"default": {"gr1"},
					},
				}
			})
			It("Should not be blocked", func() {
				resp, err = sut.Resolve(newRequestWithClient("domain1.com.", dns.TypeA, "1.2.1.2", "unknown"))

				// was delegated to next resolver
				m.AssertExpectations(GinkgoT())
			})
		})

		When("Only whitelist is defined", func() {
			BeforeEach(func() {
				sutConfig = config.BlockingConfig{
					WhiteLists: map[string][]string{"gr1": {group1File.Name()}},
					ClientGroupsBlock: map[string][]string{
						"default": {"gr1"},
					},
				}
			})
			It("should block everything else except domains on the white list", func() {
				By("querying domain on the whitelist", func() {
					resp, err = sut.Resolve(newRequestWithClient("domain1.com.", dns.TypeA, "1.2.1.2", "unknown"))

					// was delegated to next resolver
					m.AssertExpectations(GinkgoT())
				})

				By("querying another domain, which is not on the whitelist", func() {
					resp, err = sut.Resolve(newRequestWithClient("google.com.", dns.TypeA, "1.2.1.2", "unknown"))
					Expect(m.Calls).Should(HaveLen(1))
					Expect(resp.Reason).Should(Equal("BLOCKED (WHITELIST ONLY)"))
				})
			})
		})

		When("IP address is on black and white list", func() {
			BeforeEach(func() {
				sutConfig = config.BlockingConfig{
					BlackLists: map[string][]string{"gr1": {group1File.Name()}},
					WhiteLists: map[string][]string{"gr1": {defaultGroupFile.Name()}},
					ClientGroupsBlock: map[string][]string{
						"default": {"gr1"},
					},
				}
				mockAnswer, _ = util.NewMsgWithAnswer("example.com.", 300, dns.TypeA, "123.145.123.145")
			})
			It("should not block if DNS answer contains IP from the white list", func() {
				resp, err = sut.Resolve(newRequestWithClient("example.com.", dns.TypeA, "1.2.1.2", "unknown"))

				// was delegated to next resolver
				m.AssertExpectations(GinkgoT())
			})
		})
	})

	Describe("Delegate request to next resolver", func() {
		BeforeEach(func() {
			sutConfig = config.BlockingConfig{
				BlackLists: map[string][]string{"gr1": {group1File.Name()}},
				ClientGroupsBlock: map[string][]string{
					"default": {"gr1"},
				},
			}
		})
		AfterEach(func() {
			// was delegated to next resolver
			m.AssertExpectations(GinkgoT())

			Expect(resp.RType).Should(Equal(RESOLVED))
		})
		When("domain is not on the black list", func() {
			It("should delegate to next resolver", func() {
				resp, err = sut.Resolve(newRequestWithClient("example.com.", dns.TypeA, "1.2.1.2", "unknown"))
			})
		})
		When("no lists defined", func() {
			BeforeEach(func() {
				sutConfig = config.BlockingConfig{}
			})
			It("should delegate to next resolver", func() {
				resp, err = sut.Resolve(newRequestWithClient("example.com.", dns.TypeA, "1.2.1.2", "unknown"))
			})
		})

	})

	Describe("Control status via API", func() {
		BeforeEach(func() {
			sutConfig = config.BlockingConfig{
				BlackLists: map[string][]string{
					"defaultGroup": {defaultGroupFile.Name()},
					"group1":       {group1File.Name()},
				},
				ClientGroupsBlock: map[string][]string{
					"default": {"defaultGroup", "group1"},
				},
				BlockType: "ZeroIP",
			}
		})
		When("Disable blocking is called", func() {
			It("no query should be blocked", func() {
				By("Perform query to ensure that the blocking status is active (defaultGroup)", func() {
					resp, err := sut.Resolve(newRequestWithClient("blocked3.com.", dns.TypeA, "1.2.1.2", "unknown"))
					Expect(err).Should(Succeed())
					Expect(resp.RType).Should(Equal(BLOCKED))
				})

				By("Perform query to ensure that the blocking status is active (group1)", func() {
					resp, err := sut.Resolve(newRequestWithClient("domain1.com.", dns.TypeA, "1.2.1.2", "unknown"))
					Expect(err).Should(Succeed())
					Expect(resp.RType).Should(Equal(BLOCKED))
				})

				By("Calling Rest API to deactivate all groups", func() {
					err := sut.DisableBlocking(0, []string{})
					Expect(err).Should(Succeed())
				})

				By("perform the same query again (defaultGroup)", func() {
					// now is blocking disabled, query the url again
					resp, err := sut.Resolve(newRequestWithClient("blocked3.com.", dns.TypeA, "1.2.1.2", "unknown"))
					Expect(err).Should(Succeed())
					Expect(resp.RType).Should(Equal(RESOLVED))

					m.AssertExpectations(GinkgoT())
					m.AssertNumberOfCalls(GinkgoT(), "Resolve", 1)
				})

				By("perform the same query again (group1)", func() {
					// now is blocking disabled, query the url again
					resp, err := sut.Resolve(newRequestWithClient("domain1.com.", dns.TypeA, "1.2.1.2", "unknown"))
					Expect(err).Should(Succeed())
					Expect(resp.RType).Should(Equal(RESOLVED))

					m.AssertExpectations(GinkgoT())
					m.AssertNumberOfCalls(GinkgoT(), "Resolve", 2)
				})

				By("Calling Rest API to deactivate only defaultGroup", func() {
					err := sut.DisableBlocking(0, []string{"defaultGroup"})
					Expect(err).Should(Succeed())
				})

				By("perform the same query again (defaultGroup)", func() {
					// now is blocking disabled, query the url again
					resp, err := sut.Resolve(newRequestWithClient("blocked3.com.", dns.TypeA, "1.2.1.2", "unknown"))
					Expect(err).Should(Succeed())
					Expect(resp.RType).Should(Equal(RESOLVED))

					m.AssertExpectations(GinkgoT())
					m.AssertNumberOfCalls(GinkgoT(), "Resolve", 3)
				})

				By("Perform query to ensure that the blocking status is active (group1)", func() {
					resp, err := sut.Resolve(newRequestWithClient("domain1.com.", dns.TypeA, "1.2.1.2", "unknown"))
					Expect(err).Should(Succeed())
					Expect(resp.RType).Should(Equal(BLOCKED))
				})
			})
		})

		When("Disable blocking for all groups is called with a duration parameter", func() {
			It("No query should be blocked only for passed amount of time", func() {
				By("Perform query to ensure that the blocking status is active (defaultGroup)", func() {
					resp, err := sut.Resolve(newRequestWithClient("blocked3.com.", dns.TypeA, "1.2.1.2", "unknown"))
					Expect(err).Should(Succeed())
					Expect(resp.RType).Should(Equal(BLOCKED))
				})
				By("Perform query to ensure that the blocking status is active (group1)", func() {
					resp, err := sut.Resolve(newRequestWithClient("domain1.com.", dns.TypeA, "1.2.1.2", "unknown"))
					Expect(err).Should(Succeed())
					Expect(resp.RType).Should(Equal(BLOCKED))
				})

				By("Calling Rest API to deactivate blocking for 0.5 sec", func() {
					enabled := true
					err := Bus().SubscribeOnce(BlockingEnabledEvent, func(state bool) {
						enabled = state
					})
					Expect(err).Should(Succeed())
					err = sut.DisableBlocking(500*time.Millisecond, []string{})
					Expect(err).Should(Succeed())
					Expect(enabled).Should(BeFalse())
				})

				By("perform the same query again to ensure that this query will not be blocked (defaultGroup)", func() {
					// now is blocking disabled, query the url again
					resp, err := sut.Resolve(newRequestWithClient("blocked3.com.", dns.TypeA, "1.2.1.2", "unknown"))
					Expect(err).Should(Succeed())
					Expect(resp.RType).Should(Equal(RESOLVED))

					m.AssertExpectations(GinkgoT())
					m.AssertNumberOfCalls(GinkgoT(), "Resolve", 1)
				})
				By("perform the same query again to ensure that this query will not be blocked (group1)", func() {
					// now is blocking disabled, query the url again
					resp, err := sut.Resolve(newRequestWithClient("domain1.com.", dns.TypeA, "1.2.1.2", "unknown"))
					Expect(err).Should(Succeed())
					Expect(resp.RType).Should(Equal(RESOLVED))

					m.AssertExpectations(GinkgoT())
					m.AssertNumberOfCalls(GinkgoT(), "Resolve", 2)
				})

				By("Wait 1 sec and perform the same query again, should be blocked now", func() {
					enabled := false
					_ = Bus().SubscribeOnce(BlockingEnabledEvent, func(state bool) {
						enabled = state
					})
					// wait 1 sec
					time.Sleep(time.Second)
					Expect(enabled).Should(BeTrue())

					resp, err := sut.Resolve(newRequestWithClient("blocked3.com.", dns.TypeA, "1.2.1.2", "unknown"))
					Expect(err).Should(Succeed())
					Expect(resp.RType).Should(Equal(BLOCKED))

					resp, err = sut.Resolve(newRequestWithClient("domain1.com.", dns.TypeA, "1.2.1.2", "unknown"))
					Expect(err).Should(Succeed())
					Expect(resp.RType).Should(Equal(BLOCKED))
				})
			})
		})

		When("Disable blocking for one group is called with a duration parameter", func() {
			It("No query should be blocked only for passed amount of time", func() {
				By("Perform query to ensure that the blocking status is active (defaultGroup)", func() {
					resp, err := sut.Resolve(newRequestWithClient("blocked3.com.", dns.TypeA, "1.2.1.2", "unknown"))
					Expect(err).Should(Succeed())
					Expect(resp.RType).Should(Equal(BLOCKED))
				})
				By("Perform query to ensure that the blocking status is active (group1)", func() {
					resp, err := sut.Resolve(newRequestWithClient("domain1.com.", dns.TypeA, "1.2.1.2", "unknown"))
					Expect(err).Should(Succeed())
					Expect(resp.RType).Should(Equal(BLOCKED))
				})

				By("Calling Rest API to deactivate blocking for one group for 0.5 sec", func() {
					enabled := true
					err := Bus().SubscribeOnce(BlockingEnabledEvent, func(state bool) {
						enabled = state
					})
					Expect(err).Should(Succeed())
					err = sut.DisableBlocking(500*time.Millisecond, []string{"group1"})
					Expect(err).Should(Succeed())
					Expect(enabled).Should(BeFalse())
				})

				By("perform the same query again to ensure that this query will not be blocked (defaultGroup)", func() {
					// now is blocking disabled, query the url again
					resp, err := sut.Resolve(newRequestWithClient("blocked3.com.", dns.TypeA, "1.2.1.2", "unknown"))
					Expect(err).Should(Succeed())
					Expect(resp.RType).Should(Equal(BLOCKED))

				})
				By("perform the same query again to ensure that this query will not be blocked (group1)", func() {
					// now is blocking disabled, query the url again
					resp, err := sut.Resolve(newRequestWithClient("domain1.com.", dns.TypeA, "1.2.1.2", "unknown"))
					Expect(err).Should(Succeed())
					Expect(resp.RType).Should(Equal(RESOLVED))

					m.AssertExpectations(GinkgoT())
					m.AssertNumberOfCalls(GinkgoT(), "Resolve", 1)
				})

				By("Wait 1 sec and perform the same query again, should be blocked now", func() {
					enabled := false
					_ = Bus().SubscribeOnce(BlockingEnabledEvent, func(state bool) {
						enabled = state
					})
					// wait 1 sec
					time.Sleep(time.Second)
					Expect(enabled).Should(BeTrue())

					resp, err := sut.Resolve(newRequestWithClient("blocked3.com.", dns.TypeA, "1.2.1.2", "unknown"))
					Expect(err).Should(Succeed())
					Expect(resp.RType).Should(Equal(BLOCKED))

					resp, err = sut.Resolve(newRequestWithClient("domain1.com.", dns.TypeA, "1.2.1.2", "unknown"))
					Expect(err).Should(Succeed())
					Expect(resp.RType).Should(Equal(BLOCKED))
				})
			})
		})

		When("Disable blocking is called with wrong group name", func() {
			It("should fail", func() {
				err := sut.DisableBlocking(500*time.Millisecond, []string{"unknownGroupName"})
				Expect(err).Should(HaveOccurred())
			})
		})

		When("Blocking status is called", func() {
			It("should return correct status", func() {
				By("enable blocking via API", func() {
					sut.EnableBlocking()
				})

				By("Query blocking status via API should return 'enabled'", func() {
					result := sut.BlockingStatus()
					Expect(result.Enabled).Should(BeTrue())
				})

				By("disable blocking via API", func() {
					err := sut.DisableBlocking(500*time.Millisecond, []string{})
					Expect(err).Should(Succeed())
				})

				By("Query blocking status via API again should return 'disabled'", func() {
					result := sut.BlockingStatus()

					Expect(result.Enabled).Should(BeFalse())
				})
			})
		})
	})

	Describe("Configuration output", func() {
		When("resolver is enabled", func() {
			BeforeEach(func() {
				sutConfig = config.BlockingConfig{
					BlackLists: map[string][]string{"gr1": {group1File.Name()}},
					ClientGroupsBlock: map[string][]string{
						"default": {"gr1"},
					},
				}
			})
			It("should return configuration", func() {
				c := sut.Configuration()
				Expect(len(c) > 1).Should(BeTrue())
			})
		})

		When("resolver is disabled", func() {
			BeforeEach(func() {
				sutConfig = config.BlockingConfig{}
			})
		})
		It("should return 'disabled''", func() {
			c := sut.Configuration()
			Expect(c).Should(HaveLen(1))
			Expect(c).Should(Equal([]string{"deactivated"}))
		})
	})

	Describe("Create resolver with wrong parameter", func() {
		When("Wrong blockType is used", func() {
			var fatal bool
			It("should end with fatal exit", func() {
				defer func() { Log().ExitFunc = nil }()

				Log().ExitFunc = func(int) { fatal = true }

				_ = NewBlockingResolver(config.BlockingConfig{
					BlockType: "wrong",
				})

				Expect(fatal).Should(BeTrue())
			})
		})
	})

})
