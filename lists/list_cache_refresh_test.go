package lists

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"

	"github.com/0xERR0R/blocky/config"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("List refresh memory bound", func() {
	It("rebuilds one group at a time across overlapping refreshes while keeping old rules", func(ctx context.Context) {
		started := make(chan struct{}, 4)
		release := make(chan struct{})
		var refreshing atomic.Bool

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if refreshing.Load() {
				started <- struct{}{}
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
				_, _ = fmt.Fprintln(w, "*.refreshed.test")
			}
			_, _ = fmt.Fprintln(w, "*.example.test")
		}))
		DeferCleanup(server.Close)
		DeferCleanup(func() { close(release) })

		cfg, err := config.WithDefaults[config.SourceLoading]()
		Expect(err).To(Succeed())
		cfg.RefreshPeriod = -1
		cfg.Strategy = config.InitStrategyFailOnError
		cache, err := NewListCache(ctx, ListCacheTypeDenylist, cfg, map[string][]config.BytesSource{
			"one": config.NewBytesSources(server.URL),
			"two": config.NewBytesSources(server.URL),
		}, NewDownloader(cfg.Downloads, nil))
		Expect(err).To(Succeed())

		refreshing.Store(true)
		done := make(chan error, 2)
		for range 2 {
			go func() { done <- cache.Refresh(ctx) }()
		}

		for range 4 {
			Eventually(started).Should(Receive())
			Consistently(started, "50ms").ShouldNot(Receive())
			Expect(cache.Match("sub.example.test", []string{"one", "two"})).To(Equal(map[string]string{
				"one": "*.example.test", "two": "*.example.test",
			}))
			release <- struct{}{}
		}
		for range 2 {
			Eventually(done).Should(Receive(Succeed()))
		}
		Expect(cache.Match("sub.refreshed.test", []string{"one", "two"})).To(Equal(map[string]string{
			"one": "*.refreshed.test", "two": "*.refreshed.test",
		}))
	})
})
