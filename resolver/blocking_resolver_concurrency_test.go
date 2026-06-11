package resolver

import (
	"context"
	"sync"
	"time"

	"github.com/0xERR0R/blocky/config"

	. "github.com/0xERR0R/blocky/helpertest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("BlockingResolver concurrency", Label("blockingResolver"), func() {
	var (
		sut       *BlockingResolver
		sutConfig config.Blocking
		ctx       context.Context
		cancelFn  context.CancelFunc
	)

	BeforeEach(func() {
		ctx, cancelFn = context.WithCancel(context.Background())
		DeferCleanup(cancelFn)

		sutConfig = config.Blocking{
			BlockType: "ZEROIP",
			BlockTTL:  config.Duration(time.Minute),
			Denylists: map[string][]config.BytesSource{
				"gr1": config.NewBytesSources(group1File.Path),
				"gr2": config.NewBytesSources(group2File.Path),
			},
			ClientGroupsBlock: map[string][]string{
				"default": {"gr1", "gr2"},
			},
		}
	})

	JustBeforeEach(func() {
		var err error

		sut, err = NewBlockingResolver(ctx, sutConfig, systemResolverBootstrap)
		Expect(err).Should(Succeed())
	})

	// Regression test for the recursive status.lock.RLock() in
	// groupsToCheckForClient -> isGroupDisabled. Go's RWMutex forbids recursive
	// read-locking: if a writer (DisableBlocking/EnableBlocking/timer) acquires
	// the write lock between the outer read lock and the inner one, the inner
	// RLock blocks forever and the goroutine deadlocks. This stresses exactly
	// that interleaving; before the fix it hangs and the spec times out.
	It("does not deadlock when blocking is toggled concurrently with group resolution", func() {
		const (
			readers    = 8
			iterations = 20000
		)

		request := newRequestWithClient("example.com.", A, "1.2.1.2", "someclient")

		done := make(chan struct{})

		go func() {
			defer GinkgoRecover()
			defer close(done)

			var wg sync.WaitGroup

			// writer: continuously flips the blocking state, taking the write lock.
			wg.Add(1)

			go func() {
				defer GinkgoRecover()
				defer wg.Done()

				for range iterations {
					_ = sut.DisableBlocking(ctx, 0, []string{})
					sut.EnableBlocking(ctx)
				}
			}()

			// readers: resolve the per-client group set, which snapshots
			// disabledGroups under a brief read lock (the path that previously
			// recursively read-locked and deadlocked).
			for range readers {
				wg.Add(1)

				go func() {
					defer GinkgoRecover()
					defer wg.Done()

					for range iterations {
						sut.groupsToCheckForClient(request)
					}
				}()
			}

			wg.Wait()
		}()

		timeout := time.NewTimer(15 * time.Second)
		defer timeout.Stop()

		select {
		case <-done:
		case <-timeout.C:
			Fail("groupsToCheckForClient deadlocked: recursive status.lock.RLock " +
				"under concurrent blocking toggling")
		}
	})
})
