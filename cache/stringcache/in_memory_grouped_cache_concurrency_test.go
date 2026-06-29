package stringcache_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/0xERR0R/blocky/cache/stringcache"
)

// TestInMemoryGroupedCacheConcurrentRefreshAndLookup exercises lookups running
// concurrently with group refreshes. It is a safety net for the lock-free
// copy-on-write lookup path: run with -race, a torn map read or a lost refresh
// update is reported as a data race. A seed entry that every refresh re-adds must
// stay continuously matchable throughout.
func TestInMemoryGroupedCacheConcurrentRefreshAndLookup(t *testing.T) {
	t.Parallel()

	const (
		groups    = 4
		readers   = 8
		refreshes = 150
	)

	cache := stringcache.NewInMemoryGroupedStringCache()

	groupNames := make([]string, groups)
	for g := range groupNames {
		groupNames[g] = fmt.Sprintf("group%d", g)

		f := cache.Refresh(groupNames[g])
		f.AddEntry("seed.example")
		f.Finish()
	}

	stop := make(chan struct{})

	var readWG sync.WaitGroup

	for range readers {
		readWG.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
					if m := cache.Contains("seed.example", groupNames); len(m) != groups {
						t.Errorf("seed entry must match all %d groups, got %d", groups, len(m))

						return
					}

					cache.ElementCount(groupNames[0])
				}
			}
		})
	}

	var writeWG sync.WaitGroup

	for gi, group := range groupNames {
		writeWG.Go(func() {
			for j := range refreshes {
				f := cache.Refresh(group)
				f.AddEntry(fmt.Sprintf("e%d-%d.example", gi, j))
				f.AddEntry("seed.example") // keep the invariant the readers assert
				f.Finish()
			}
		})
	}

	writeWG.Wait()
	close(stop)
	readWG.Wait()
}
