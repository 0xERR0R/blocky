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

		ctx      context.Context
		cancelFn context.CancelFunc
	)

	Describe("Type", func() {
		It("follows conventions", func() {
			ctx, cancelFn = context.WithCancel(context.Background())
			DeferCleanup(cancelFn)

			sut = NewStatsResolver(ctx, config.Statistics{Enable: true})
			expectValidResolverType(sut)
		})
	})

	Context("when enabled", func() {
		BeforeEach(func() {
			ctx, cancelFn = context.WithCancel(context.Background())
			DeferCleanup(cancelFn)

			sut = NewStatsResolver(ctx, config.Statistics{Enable: true})
			m = &mockResolver{}
			sut.Next(m)
		})

		It("reports enabled", func() {
			Expect(sut.IsEnabled()).Should(BeTrue())
			Expect(sut.StatsEnabled()).Should(BeTrue())
		})

		It("records a resolved query", func() {
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

		It("records a rate-limiter drop as dropped", func() {
			m.On("Resolve", mock.Anything).Return(nil, ErrRateLimited)

			_, err := sut.Resolve(ctx, newRequestWithClient("dropped.com.", A, "1.2.3.4", "client1"))
			Expect(err).Should(MatchError(ErrRateLimited))

			Eventually(func() int {
				return sut.Stats().Summary.Dropped
			}).Should(Equal(1))
		})

		It("records other errors as errors", func() {
			m.On("Resolve", mock.Anything).Return(nil, errors.New("boom"))

			_, err := sut.Resolve(ctx, newRequestWithClient("err.com.", A, "1.2.3.4", "client1"))
			Expect(err).Should(HaveOccurred())

			Eventually(func() int {
				return sut.Stats().Summary.Errors
			}).Should(Equal(1))
		})

		It("logs config", func() {
			logger, hook := log.NewMockEntry()
			sut.LogConfig(logger)
			Expect(hook.Calls).ShouldNot(BeEmpty())
		})

		It("updates cache entry count from the event bus", func() {
			evt.Bus().Publish(evt.CachingResultCacheChanged, 123)

			Eventually(func() int {
				return sut.Stats().CacheEntries
			}).Should(Equal(123))
		})

		It("updates list counts from the event bus", func() {
			evt.Bus().Publish(evt.BlockingCacheGroupChanged, lists.ListCacheTypeDenylist, "ads", 5000)

			Eventually(func() map[string]int {
				return sut.Stats().Lists.Denylist
			}).Should(HaveKeyWithValue("ads", 5000))
		})
	})

	Context("when disabled", func() {
		BeforeEach(func() {
			ctx, cancelFn = context.WithCancel(context.Background())
			DeferCleanup(cancelFn)

			sut = NewStatsResolver(ctx, config.Statistics{Enable: false})
			m = &mockResolver{}
			m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg), RType: ResponseTypeRESOLVED}, nil)
			sut.Next(m)
		})

		It("is a pass-through and reports disabled", func() {
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
