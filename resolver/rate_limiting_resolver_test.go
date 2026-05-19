package resolver

import (
	"context"
	"errors"
	"time"

	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/log"
	. "github.com/0xERR0R/blocky/model"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("RateLimitingResolver", func() {
	var (
		sut       *RateLimitingResolver
		sutConfig config.RateLimit
		m         *mockResolver
		ctx       context.Context
		cancelFn  context.CancelFunc
	)

	BeforeEach(func() {
		ctx, cancelFn = context.WithCancel(context.Background())
		DeferCleanup(cancelFn)
	})

	JustBeforeEach(func() {
		sut = NewRateLimitingResolver(sutConfig)
		m = &mockResolver{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
		sut.Next(m)
	})

	Describe("Type", func() {
		It("follows conventions", func() {
			expectValidResolverType(sut)
		})
	})

	Describe("LogConfig", func() {
		BeforeEach(func() {
			sutConfig = config.RateLimit{Enable: true, Rate: 1, Burst: 1, IPv4Prefix: 32, IPv6Prefix: 64}
		})
		It("emits something", func() {
			logger, hook := log.NewMockEntry()
			sut.LogConfig(logger)
			Expect(hook.Calls).ShouldNot(BeEmpty())
		})
	})

	When("disabled", func() {
		BeforeEach(func() {
			sutConfig = config.RateLimit{Enable: false}
		})
		It("delegates every request to next", func() {
			req := newRequestWithClient("example.com.", A, "1.2.3.4")
			_, err := sut.Resolve(ctx, req)
			Expect(err).Should(Succeed())
			Expect(m.Calls).Should(HaveLen(1))
		})
		It("IsEnabled is false", func() {
			Expect(sut.IsEnabled()).Should(BeFalse())
		})
	})

	When("enabled with allowlist", func() {
		BeforeEach(func() {
			sutConfig = config.RateLimit{
				Enable: true, Rate: 1, Burst: 1,
				IPv4Prefix: 32, IPv6Prefix: 64,
				Allowlist: []string{"10.0.0.0/8"},
			}
			Expect(sutConfig.Validate_forTest()).Should(Succeed())
		})
		It("bypasses allowlisted clients regardless of bucket", func() {
			req := newRequestWithClient("example.com.", A, "10.1.2.3")
			for range 5 {
				_, err := sut.Resolve(ctx, req)
				Expect(err).Should(Succeed())
			}
		})
		It("bypasses requests with nil ClientIP", func() {
			req := newRequest("example.com.", A) // no client IP set
			for range 5 {
				_, err := sut.Resolve(ctx, req)
				Expect(err).Should(Succeed())
			}
		})
	})

	When("enabled with rate=1 burst=1", func() {
		var fakeNow time.Time
		BeforeEach(func() {
			fakeNow = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			sutConfig = config.RateLimit{
				Enable: true, Rate: 1, Burst: 1,
				IPv4Prefix: 32, IPv6Prefix: 64,
			}
			Expect(sutConfig.Validate_forTest()).Should(Succeed())
		})
		JustBeforeEach(func() {
			sut.clock = func() time.Time { return fakeNow }
		})

		It("allows first request, drops second", func() {
			req := newRequestWithClient("example.com.", A, "1.2.3.4")
			_, err := sut.Resolve(ctx, req)
			Expect(err).Should(Succeed())

			_, err = sut.Resolve(ctx, req)
			Expect(errors.Is(err, ErrRateLimited)).Should(BeTrue())
			Expect(m.Calls).Should(HaveLen(1)) // second never reached next
		})

		It("allows again after enough time has elapsed", func() {
			req := newRequestWithClient("example.com.", A, "1.2.3.4")
			_, _ = sut.Resolve(ctx, req)
			fakeNow = fakeNow.Add(2 * time.Second)
			_, err := sut.Resolve(ctx, req)
			Expect(err).Should(Succeed())
		})

		It("uses separate buckets for different /32s", func() {
			r1 := newRequestWithClient("example.com.", A, "1.2.3.4")
			r2 := newRequestWithClient("example.com.", A, "5.6.7.8")
			_, e1 := sut.Resolve(ctx, r1)
			_, e2 := sut.Resolve(ctx, r2)
			Expect(e1).Should(Succeed())
			Expect(e2).Should(Succeed())
		})
	})
})
