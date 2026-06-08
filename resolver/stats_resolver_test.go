package resolver

import (
	"context"
	"errors"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/evt"
	"github.com/0xERR0R/blocky/lists"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/stats"

	. "github.com/0xERR0R/blocky/helpertest"
	. "github.com/0xERR0R/blocky/model"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("StatsResolver", func() {
	var (
		sut *StatsResolver
		m   *mockResolver
	)

	Describe("Type", func() {
		It("follows conventions", func(ctx context.Context) {
			sut = NewStatsResolver(ctx, config.Statistics{Enable: true})
			expectValidResolverType(sut)
		})
	})

	Context("when enabled", func() {
		// start builds the SUT with the spec's context so Ginkgo tears down the
		// consumer goroutine and the event-bus subscriptions automatically when the
		// spec ends — no manual context.WithCancel/DeferCleanup needed.
		start := func(ctx context.Context) {
			sut = NewStatsResolver(ctx, config.Statistics{Enable: true})
			sut.Next(m)
		}

		BeforeEach(func() {
			m = &mockResolver{}
		})

		It("reports enabled", func(ctx context.Context) {
			start(ctx)

			Expect(sut.IsEnabled()).Should(BeTrue())
			Expect(sut.StatsEnabled()).Should(BeTrue())
		})

		It("records a resolved query", func(ctx context.Context) {
			start(ctx)
			m.On("Resolve", mock.Anything).Return(
				&Response{Res: new(dns.Msg), RType: ResponseTypeRESOLVED, Reason: "RESOLVED"}, nil)

			_, err := sut.Resolve(ctx, newRequestWithClient("example.com.", A, "1.2.3.4", "client1"))
			Expect(err).Should(Succeed())

			Eventually(func() int {
				return sut.Stats().Summary.Queries
			}).Should(Equal(1))

			res := sut.Stats()
			Expect(res.ByResponseType).Should(HaveKeyWithValue("RESOLVED", 1))
			Expect(namesOf(res.TopDomains)).Should(ContainElement("example.com"))
			Expect(namesOf(res.TopClients)).Should(ContainElement("client1"))
		})

		It("records a rate-limiter drop as dropped", func(ctx context.Context) {
			start(ctx)
			m.On("Resolve", mock.Anything).Return(nil, ErrRateLimited)

			_, err := sut.Resolve(ctx, newRequestWithClient("dropped.com.", A, "1.2.3.4", "client1"))
			Expect(err).Should(MatchError(ErrRateLimited))

			Eventually(func() int {
				return sut.Stats().Summary.Dropped
			}).Should(Equal(1))
		})

		It("records other errors as errors", func(ctx context.Context) {
			start(ctx)
			m.On("Resolve", mock.Anything).Return(nil, errors.New("boom"))

			_, err := sut.Resolve(ctx, newRequestWithClient("err.com.", A, "1.2.3.4", "client1"))
			Expect(err).Should(HaveOccurred())

			Eventually(func() int {
				return sut.Stats().Summary.Errors
			}).Should(Equal(1))
		})

		It("logs config", func(ctx context.Context) {
			start(ctx)
			logger, hook := log.NewMockEntry()
			sut.LogConfig(logger)
			Expect(hook.Calls).ShouldNot(BeEmpty())
		})

		It("updates cache entry count from the event bus", func(ctx context.Context) {
			start(ctx)
			evt.Bus().Publish(evt.CachingResultCacheChanged, 123)

			Eventually(func() int {
				return sut.Stats().CacheEntries
			}).Should(Equal(123))
		})

		It("updates list counts from the event bus", func(ctx context.Context) {
			start(ctx)
			evt.Bus().Publish(evt.BlockingCacheGroupChanged, lists.ListCacheTypeDenylist, "ads", 5000)

			Eventually(func() map[string]int {
				return sut.Stats().Lists.Denylist
			}).Should(HaveKeyWithValue("ads", 5000))
		})
	})

	Context("when disabled", func() {
		BeforeEach(func() {
			m = &mockResolver{}
			m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg), RType: ResponseTypeRESOLVED}, nil)
		})

		It("is a pass-through and reports disabled", func(ctx context.Context) {
			sut = NewStatsResolver(ctx, config.Statistics{Enable: false})
			sut.Next(m)

			Expect(sut.StatsEnabled()).Should(BeFalse())

			_, err := sut.Resolve(ctx, newRequestWithClient("example.com.", A, "1.2.3.4", "client1"))
			Expect(err).Should(Succeed())

			Expect(sut.Stats().Summary.Queries).Should(Equal(0))
			m.AssertExpectations(GinkgoT())
		})
	})
})

func namesOf(in []stats.NameCount) []string {
	out := make([]string, 0, len(in))
	for _, nc := range in {
		out = append(out, nc.Name)
	}

	return out
}
