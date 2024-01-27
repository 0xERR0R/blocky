package resolver

import (
	"context"
	"fmt"

	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/log"
	. "github.com/0xERR0R/blocky/model"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("UpstreamTreeResolver", Label("upstreamTreeResolver"), func() {
	var (
		sut       Resolver
		sutConfig config.Upstreams

		err error

		ctx      context.Context
		cancelFn context.CancelFunc
	)

	BeforeEach(func() {
		ctx, cancelFn = context.WithCancel(context.Background())
		DeferCleanup(cancelFn)

		sutConfig = defaultUpstreamsConfig
	})

	JustBeforeEach(func() {
		sut, err = NewUpstreamTreeResolver(ctx, sutConfig, systemResolverBootstrap)
	})

	When("it has no configuration", func() {
		BeforeEach(func() {
			sutConfig = config.Upstreams{}
		})

		It("should return error", func() {
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(ContainSubstring("no external DNS resolvers configured")))
			Expect(sut).To(BeNil())
		})
	})

	When("it has only default group", func() {
		BeforeEach(func() {
			sutConfig.Groups = config.UpstreamGroups{
				upstreamDefaultCfgName: {
					{Host: "wrong"},
					{Host: "127.0.0.1"},
				},
			}
		})

		When("strategy is parallel", func() {
			BeforeEach(func() {
				sutConfig.Strategy = config.UpstreamStrategyParallelBest
			})

			It("returns the resolver directly", func() {
				Expect(err).ToNot(HaveOccurred())

				_, ok := sut.(*ParallelBestResolver)
				Expect(ok).Should(BeTrue())
			})
		})

		When("strategy is strict", func() {
			BeforeEach(func() {
				sutConfig.Strategy = config.UpstreamStrategyStrict
			})

			It("returns the resolver directly", func() {
				Expect(err).ToNot(HaveOccurred())

				_, ok := sut.(*StrictResolver)
				Expect(ok).Should(BeTrue())
			})
		})
	})

	When("it has multiple groups", func() {
		BeforeEach(func() {
			sutConfig.Groups = config.UpstreamGroups{
				upstreamDefaultCfgName: {
					{Host: "wrong"},
					{Host: "127.0.0.1"},
				},
				"test": {
					{Host: "some-resolver"},
				},
			}
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

		When("init strategy is failOnError", func() {
			BeforeEach(func() {
				sutConfig.Init.Strategy = config.InitStrategyFailOnError
			})

			It("should fail", func() {
				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError(ContainSubstring("no valid upstream")))
				Expect(sut).To(BeNil())
			})
		})

		When("client specific resolvers are defined", func() {
			groups := map[string]string{
				upstreamDefaultCfgName: "127.0.0.1",
				"laptop":               "127.0.0.2",
				"client-*-m":           "127.0.0.3",
				"client[0-9]":          "127.0.0.4",
				"192.168.178.33":       "127.0.0.5",
				"10.43.8.67/28":        "127.0.0.6",
				"name-matches1":        "127.0.0.7",
				"name-matches*":        "127.0.0.8",
			}

			BeforeEach(func() {
				sutConfig.Groups = make(config.UpstreamGroups, len(groups))

				for group, ip := range groups {
					Expect(ip).ShouldNot(BeNil())

					server := NewMockUDPUpstreamServer().WithAnswerRR(fmt.Sprintf("example.com 123 IN A %s", ip))
					sutConfig.Groups[group] = []config.Upstream{server.Start()}
				}
			})

			It("Should use default if client name or IP don't match", func() {
				request := newRequestWithClient("example.com.", A, "192.168.178.55", "test")

				Expect(sut.Resolve(ctx, request)).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, groups["default"]),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
			It("Should use client specific resolver if client name matches exact", func() {
				request := newRequestWithClient("example.com.", A, "192.168.178.55", "laptop")

				Expect(sut.Resolve(ctx, request)).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, groups["laptop"]),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
			It("Should use client specific resolver if client name matches with wildcard", func() {
				request := newRequestWithClient("example.com.", A, "192.168.178.55", "client-test-m")

				Expect(sut.Resolve(ctx, request)).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, groups["client-*-m"]),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
			It("Should use client specific resolver if client name matches with range wildcard", func() {
				request := newRequestWithClient("example.com.", A, "192.168.178.55", "client7")

				Expect(sut.Resolve(ctx, request)).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, groups["client[0-9]"]),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
			It("Should use client specific resolver if client IP matches", func() {
				request := newRequestWithClient("example.com.", A, "192.168.178.33", "noname")

				Expect(sut.Resolve(ctx, request)).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, groups["192.168.178.33"]),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
			It("Should use client specific resolver if client name (containing IP) matches", func() {
				request := newRequestWithClient("example.com.", A, "0.0.0.0", "192.168.178.33")

				Expect(sut.Resolve(ctx, request)).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, groups["192.168.178.33"]),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
			It("Should use client specific resolver if client's CIDR (10.43.8.64 - 10.43.8.79) matches", func() {
				request := newRequestWithClient("example.com.", A, "10.43.8.70", "noname")

				Expect(sut.Resolve(ctx, request)).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, groups["10.43.8.67/28"]),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
			It("Should use exact IP match before client name match", func() {
				request := newRequestWithClient("example.com.", A, "192.168.178.33", "laptop")

				Expect(sut.Resolve(ctx, request)).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, groups["192.168.178.33"]),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
			It("Should use client name match before CIDR match", func() {
				request := newRequestWithClient("example.com.", A, "10.43.8.70", "laptop")

				Expect(sut.Resolve(ctx, request)).
					Should(
						SatisfyAll(
							BeDNSRecord("example.com.", A, groups["laptop"]),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))
			})
			It("Should use one of the matching resolvers & log warning", func() {
				logger, hook := log.NewMockEntry()

				ctx, _ = log.NewCtx(ctx, logger)

				Expect(sut.Resolve(ctx, newRequestWithClient("example.com.", A, "0.0.0.0", "name-matches1"))).
					Should(
						SatisfyAll(
							SatisfyAny(
								BeDNSRecord("example.com.", A, groups["name-matches1"]),
								BeDNSRecord("example.com.", A, groups["name-matches*"]),
							),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))

				Expect(hook.Messages).Should(ContainElement(ContainSubstring("client matches multiple groups")))
			})
		})
	})
})
