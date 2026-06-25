package resolver

import (
	"context"
	"net"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/util"
	"github.com/creasty/defaults"

	. "github.com/0xERR0R/blocky/helpertest"
	. "github.com/0xERR0R/blocky/model"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("ECSClientResolver", func() {
	var (
		sut       *ECSClientResolver
		sutConfig config.ECS
		m         *mockResolver
		origIP    net.IP
		ecsIP     net.IP
	)

	BeforeEach(func() {
		Expect(defaults.Set(&sutConfig)).Should(Succeed())
		sutConfig.UseAsClient = true

		origIP = net.ParseIP("1.2.3.4").To4()
		ecsIP = net.ParseIP("4.3.2.1").To4()
	})

	JustBeforeEach(func() {
		m = &mockResolver{}
		m.On("Resolve", mock.Anything).Return(respondWith(new(dns.Msg)), nil)

		sut = NewECSClientResolver(sutConfig).(*ECSClientResolver)
		sut.Next(m)
	})

	Describe("Type", func() {
		It("follows conventions", func() {
			expectValidResolverType(sut)
		})
	})

	When("useAsClient is enabled and a full-prefix (/32) ECS option is present", func() {
		It("adopts the ECS address as the internal client IP", func(ctx context.Context) {
			request := newRequest("example.com.", A)
			request.ClientIP = origIP
			addEcsOption(request.Req, ecsIP, ecsMaskIPv4)

			m.ResolveFn = func(_ context.Context, req *Request) (*Response, error) {
				Expect(req.ClientIP).Should(Equal(ecsIP))

				return respondWith(new(dns.Msg)), nil
			}

			_, err := sut.Resolve(ctx, request)
			Expect(err).Should(Succeed())
		})
	})

	When("the ECS option only covers a partial prefix (/24)", func() {
		It("keeps the original client IP", func(ctx context.Context) {
			request := newRequest("example.com.", A)
			request.ClientIP = origIP
			addEcsOption(request.Req, ecsIP, 24)

			m.ResolveFn = func(_ context.Context, req *Request) (*Response, error) {
				Expect(req.ClientIP).Should(Equal(origIP))

				return respondWith(new(dns.Msg)), nil
			}

			_, err := sut.Resolve(ctx, request)
			Expect(err).Should(Succeed())
		})
	})

	When("useAsClient is disabled", func() {
		BeforeEach(func() {
			sutConfig.UseAsClient = false
		})

		It("keeps the original client IP even with a full-prefix ECS option", func(ctx context.Context) {
			request := newRequest("example.com.", A)
			request.ClientIP = origIP
			addEcsOption(request.Req, ecsIP, ecsMaskIPv4)

			m.ResolveFn = func(_ context.Context, req *Request) (*Response, error) {
				Expect(req.ClientIP).Should(Equal(origIP))

				return respondWith(new(dns.Msg)), nil
			}

			_, err := sut.Resolve(ctx, request)
			Expect(err).Should(Succeed())
		})
	})
})

// Regression test for https://github.com/0xERR0R/blocky/issues/2140
//
// With ecs.useAsClient, the EDNS Client Subnet address must be adopted as the internal
// client IP *before* the client-name lookup and the cache, so that:
//   - the client name is resolved from the ECS client (not the connecting forwarder), and
//   - cached responses are still attributed to the ECS client (the cache short-circuits the
//     chain on a hit, so anything below it never runs for cached answers).
var _ = Describe("ECS as client across the resolver chain (issue #2140)", func() {
	var (
		ecsClient   *ECSClientResolver
		upstream    *mockResolver
		ecsIP       net.IP
		forwarderIP net.IP
	)

	BeforeEach(func(ctx context.Context) {
		ecsIP = net.ParseIP("4.3.2.1").To4()
		forwarderIP = net.ParseIP("1.2.3.4").To4()

		// upstream returns a cacheable answer
		answer, err := util.NewMsgWithAnswer("example.com.", 300, A, "9.9.9.9")
		Expect(err).Should(Succeed())

		upstream = &mockResolver{}
		upstream.On("Resolve", mock.Anything).
			Return(&Response{Res: answer, RType: ResponseTypeRESOLVED, Reason: "Test"}, nil)

		// caching resolver (enabled with defaults)
		var cachingCfg config.Caching
		Expect(defaults.Set(&cachingCfg)).Should(Succeed())

		caching, err := NewCachingResolver(ctx, cachingCfg, nil)
		Expect(err).Should(Succeed())
		caching.Next(upstream)

		// client names resolver resolves the ECS client IP -> name from an in-memory
		// mapping, so no rDNS upstream is required for the test
		clientNames, err := NewClientNamesResolver(ctx, config.ClientLookup{
			ClientnameIPMapping: map[string][]net.IP{"ecs-client": {ecsIP}},
		}, defaultUpstreamsConfig, nil)
		Expect(err).Should(Succeed())
		clientNames.Next(caching)

		// ECS-as-client runs ABOVE the client-name lookup and the cache
		var ecsCfg config.ECS
		Expect(defaults.Set(&ecsCfg)).Should(Succeed())
		ecsCfg.UseAsClient = true

		ecsClient = NewECSClientResolver(ecsCfg).(*ECSClientResolver)
		ecsClient.Next(clientNames)
	})

	newECSRequest := func() *Request {
		req := newRequest("example.com.", A)
		req.ClientIP = forwarderIP // the connecting forwarder, e.g. the opnsense router
		addEcsOption(req.Req, ecsIP, ecsMaskIPv4)

		return req
	}

	It("attributes both the resolved and the cached response to the ECS client", func(ctx context.Context) {
		By("resolving the first query upstream", func() {
			req := newECSRequest()

			resp, err := ecsClient.Resolve(ctx, req)
			Expect(err).Should(Succeed())
			Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
			Expect(req.ClientIP).Should(Equal(ecsIP))
			Expect(req.ClientNames).Should(Equal([]string{"ecs-client"}))
		})

		By("serving the second identical query from cache, still attributed to the ECS client", func() {
			req := newECSRequest()

			resp, err := ecsClient.Resolve(ctx, req)
			Expect(err).Should(Succeed())
			Expect(resp.RType).Should(Equal(ResponseTypeCACHED))
			Expect(req.ClientIP).Should(Equal(ecsIP))
			Expect(req.ClientNames).Should(Equal([]string{"ecs-client"}))
		})
	})
})
