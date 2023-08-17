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
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/mock"
)

var mockRes *mockResolver

var _ = Describe("UpstreamTreeResolver", Label("upstreamTreeResolver"), func() {
	var (
		sut       Resolver
		sutConfig config.UpstreamsConfig
		branches  map[string]Resolver

		loggerHook *test.Hook

		err error
	)

	BeforeEach(func() {
		mockRes = &mockResolver{}
	})

	JustBeforeEach(func() {
		sut, err = NewUpstreamTreeResolver(sutConfig, branches)
	})

	When("has no configuration", func() {
		BeforeEach(func() {
			sutConfig = config.UpstreamsConfig{}
		})

		It("should return error", func() {
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(ContainSubstring("no external DNS resolvers configured")))
			Expect(sut).To(BeNil())
		})
	})

	When("amount of passed in resolvers doesn't match amount of groups", func() {
		BeforeEach(func() {
			sutConfig = config.UpstreamsConfig{
				Groups: config.UpstreamGroups{
					upstreamDefaultCfgName: {
						{Host: "wrong"},
						{Host: "127.0.0.1"},
					},
				},
			}
			branches = map[string]Resolver{}
		})

		It("should return error", func() {
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(
				"amount of passed in branches (0) does not match amount of configured upstream groups (1)"))
			Expect(sut).To(BeNil())
		})
	})

	When("has only default group", func() {
		BeforeEach(func() {
			sutConfig = config.UpstreamsConfig{
				Groups: config.UpstreamGroups{
					upstreamDefaultCfgName: {
						{Host: "wrong"},
						{Host: "127.0.0.1"},
					},
				},
			}
			branches = createBranchesMock(sutConfig)
		})
		Describe("Type", func() {
			It("does not return error", func() {
				Expect(err).ToNot(HaveOccurred())
			})
			It("follows conventions", func() {
				expectValidResolverType(sut)
			})
			It("returns mock", func() {
				Expect(sut.Type()).To(Equal("mock"))
			})
		})
	})

	When("has multiple groups", func() {
		BeforeEach(func() {
			sutConfig = config.UpstreamsConfig{
				Groups: config.UpstreamGroups{
					upstreamDefaultCfgName: {
						{Host: "wrong"},
						{Host: "127.0.0.1"},
					},
					"test": {
						{Host: "some-resolver"},
					},
				},
			}
			branches = createBranchesMock(sutConfig)
		})
		Describe("Type", func() {
			It("does not return error", func() {
				Expect(err).ToNot(HaveOccurred())
			})
			It("follows conventions", func() {
				expectValidResolverType(sut)
			})
			It("returns upstream_tree", func() {
				Expect(sut.Type()).To(Equal(upstreamTreeResolverType))
			})
		})
		Describe("Configuration output", func() {
			It("should return configuration", func() {
				Expect(sut.IsEnabled()).Should(BeTrue())

				logger, hook := log.NewMockEntry()
				sut.LogConfig(logger)
				Expect(hook.Calls).ToNot(BeEmpty())
			})
		})

		Describe("Name", func() {
			var utrSut *UpstreamTreeResolver
			JustBeforeEach(func() {
				utrSut = sut.(*UpstreamTreeResolver)
			})

			It("should contain correct resolver", func() {
				name := utrSut.Name()
				Expect(name).ShouldNot(BeEmpty())
				Expect(name).Should(ContainSubstring(upstreamTreeResolverType))
			})
		})

		When("client specific resolvers are defined", func() {
			BeforeEach(func() {
				loggerHook = test.NewGlobal()
				log.Log().AddHook(loggerHook)

				sutConfig = config.UpstreamsConfig{Groups: config.UpstreamGroups{
					upstreamDefaultCfgName: {config.Upstream{}},
					"laptop":               {config.Upstream{}},
					"client-*-m":           {config.Upstream{}},
					"client[0-9]":          {config.Upstream{}},
					"192.168.178.33":       {config.Upstream{}},
					"10.43.8.67/28":        {config.Upstream{}},
					"name-matches1":        {config.Upstream{}},
					"name-matches*":        {config.Upstream{}},
				}}

				createMockResolver := func(group string) *mockResolver {
					resolver := &mockResolver{}

					resolver.On("Resolve", mock.Anything)
					resolver.ResponseFn = func(req *dns.Msg) *dns.Msg {
						res := new(dns.Msg)
						res.SetReply(req)

						ptr := new(dns.PTR)
						ptr.Ptr = group
						ptr.Hdr = util.CreateHeader(req.Question[0], 1)
						res.Answer = append(res.Answer, ptr)

						return res
					}

					return resolver
				}

				branches = map[string]Resolver{
					upstreamDefaultCfgName: nil,
					"laptop":               nil,
					"client-*-m":           nil,
					"client[0-9]":          nil,
					"192.168.178.33":       nil,
					"10.43.8.67/28":        nil,
					"name-matches1":        nil,
					"name-matches*":        nil,
				}

				for group := range branches {
					branches[group] = createMockResolver(group)
				}

				Expect(branches).To(HaveLen(8))
			})

			AfterEach(func() {
				loggerHook.Reset()
			})

			It("Should use default if client name or IP don't match", func() {
				request := newRequestWithClient("example.com.", A, "192.168.178.55", "test")

				Expect(sut.Resolve(request)).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, "default"),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
			It("Should use client specific resolver if client name matches exact", func() {
				request := newRequestWithClient("example.com.", A, "192.168.178.55", "laptop")

				Expect(sut.Resolve(request)).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, "laptop"),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
			It("Should use client specific resolver if client name matches with wildcard", func() {
				request := newRequestWithClient("example.com.", A, "192.168.178.55", "client-test-m")

				Expect(sut.Resolve(request)).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, "client-*-m"),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
			It("Should use client specific resolver if client name matches with range wildcard", func() {
				request := newRequestWithClient("example.com.", A, "192.168.178.55", "client7")

				Expect(sut.Resolve(request)).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, "client[0-9]"),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
			It("Should use client specific resolver if client IP matches", func() {
				request := newRequestWithClient("example.com.", A, "192.168.178.33", "noname")

				Expect(sut.Resolve(request)).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, "192.168.178.33"),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
			It("Should use client specific resolver if client name (containing IP) matches", func() {
				request := newRequestWithClient("example.com.", A, "0.0.0.0", "192.168.178.33")

				Expect(sut.Resolve(request)).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, "192.168.178.33"),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
			It("Should use client specific resolver if client's CIDR (10.43.8.64 - 10.43.8.79) matches", func() {
				request := newRequestWithClient("example.com.", A, "10.43.8.70", "noname")

				Expect(sut.Resolve(request)).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, "10.43.8.67/28"),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
			It("Should use exact IP match before client name match", func() {
				request := newRequestWithClient("example.com.", A, "192.168.178.33", "laptop")

				Expect(sut.Resolve(request)).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, "192.168.178.33"),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
			It("Should use client name match before CIDR match", func() {
				request := newRequestWithClient("example.com.", A, "10.43.8.70", "laptop")

				Expect(sut.Resolve(request)).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, "laptop"),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
			It("Should use one of the matching resolvers & log warning", func() {
				request := newRequestWithClient("example.com.", A, "0.0.0.0", "name-matches1")

				Expect(sut.Resolve(request)).
					Should(
						SatisfyAll(
							SatisfyAny(
								BeDNSRecord("example.com.", A, "name-matches1"),
								BeDNSRecord("example.com.", A, "name-matches*"),
							),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))

				Expect(loggerHook.LastEntry().Message).Should(ContainSubstring("client matches multiple groups"))
			})
		})
	})
})

func createBranchesMock(cfg config.UpstreamsConfig) map[string]Resolver {
	branches := make(map[string]Resolver, len(cfg.Groups))

	for name := range cfg.Groups {
		branches[name] = mockRes
	}

	return branches
}
