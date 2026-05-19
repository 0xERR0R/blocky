package resolver

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/log"
	. "github.com/0xERR0R/blocky/model"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus/testutil"
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
			Expect(sutConfig.ValidateForTest()).Should(Succeed())
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
			Expect(sutConfig.ValidateForTest()).Should(Succeed())
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

		It("increments the drops counter on each drop", func() {
			req := newRequestWithClient("example.com.", A, "1.2.3.4")
			_, _ = sut.Resolve(ctx, req) // allowed
			_, _ = sut.Resolve(ctx, req) // drop 1
			_, _ = sut.Resolve(ctx, req) // drop 2
			Expect(testutil.ToFloat64(sut.drops.WithLabelValues("UDP"))).
				Should(BeNumerically("==", 2))
		})

		It("logs at most once per second per bucket", func() {
			req := newRequestWithClient("example.com.", A, "1.2.3.4")
			logger, hook := log.NewMockEntry()
			sut.logger = logger

			_, _ = sut.Resolve(ctx, req) // allowed
			_, _ = sut.Resolve(ctx, req) // drop, log #1
			_, _ = sut.Resolve(ctx, req) // drop in same second, no log
			Expect(hook.Calls).Should(HaveLen(1))

			fakeNow = fakeNow.Add(2 * time.Second)
			_, _ = sut.Resolve(ctx, req) // allowed (token refilled after 2 s)
			_, _ = sut.Resolve(ctx, req) // drop, log #2 (window expired)
			Expect(hook.Calls).Should(HaveLen(2))
		})

		It("active-buckets gauge reflects store size", func() {
			req := newRequestWithClient("example.com.", A, "1.2.3.4")
			_, _ = sut.Resolve(ctx, req)
			Expect(testutil.ToFloat64(sut.activeBuckets)).Should(BeNumerically("==", 1))
		})

		It("aggregates IPv6 by /64 into one bucket", func() {
			r1 := newRequestWithClient("example.com.", A, "2001:db8::1")
			r2 := newRequestWithClient("example.com.", A, "2001:db8::ffff")
			_, e1 := sut.Resolve(ctx, r1)
			_, e2 := sut.Resolve(ctx, r2)
			Expect(e1).Should(Succeed())
			Expect(errors.Is(e2, ErrRateLimited)).Should(BeTrue())
		})

		It("normalises IPv4-mapped IPv6 to one bucket with IPv4", func() {
			r1 := newRequestWithClient("example.com.", A, "192.0.2.5")
			r2 := newRequestWithClient("example.com.", A, "::ffff:192.0.2.5")
			_, e1 := sut.Resolve(ctx, r1)
			_, e2 := sut.Resolve(ctx, r2)
			Expect(e1).Should(Succeed())
			Expect(errors.Is(e2, ErrRateLimited)).Should(BeTrue())
		})

		It("does not panic when a drop is logged for a malformed empty-question request", func() {
			req := &Request{
				ClientIP: net.ParseIP("1.2.3.4"),
				Req:      new(dns.Msg),
				Protocol: RequestProtocolUDP,
			}
			_, _ = sut.Resolve(ctx, req) // first allowed (or dropped — bucket=1/1 from prior tests; doesn't matter)
			Expect(func() { _, _ = sut.Resolve(ctx, req) }).ShouldNot(Panic())
		})
	})
})
