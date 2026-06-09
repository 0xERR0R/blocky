package resolver

import (
	"context"
	"fmt"
	"testing"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"

	"github.com/creasty/defaults"
	"github.com/miekg/dns"
)

// benchBackend is a zero-overhead next resolver that always returns a cacheable
// A-record answer for the requested name, so the cache can be warmed before measuring.
type benchBackend struct {
	NoOpResolver
}

func (benchBackend) Resolve(_ context.Context, req *model.Request) (*model.Response, error) {
	resp := new(dns.Msg)
	resp.SetReply(req.Req)

	rr, err := dns.NewRR(req.Req.Question[0].Name + " 3600 IN A 1.2.3.4")
	if err != nil {
		return nil, err
	}

	resp.Answer = []dns.RR{rr}

	return &model.Response{Res: resp, RType: model.ResponseTypeRESOLVED, Reason: "BENCH"}, nil
}

// BenchmarkCachingResolverResolve drives Resolve on a pre-warmed result cache
// under concurrency (every iteration is a cache hit). Run before/after sharding:
//
//	go test -run=^$ -bench=BenchmarkCachingResolverResolve -benchmem -cpu=1,2,4,8 ./resolver/
func BenchmarkCachingResolverResolve(b *testing.B) {
	// Working set must stay well under the cache capacity (default 10,000) so that no
	// shard overflows and evicts — otherwise N>1 would turn warmed keys into misses and
	// the benchmark would measure eviction artifacts instead of the all-hits path.
	const numDomains = 5_000

	cfg := config.Caching{}
	if err := defaults.Set(&cfg); err != nil {
		b.Fatal(err)
	}

	ctx := b.Context()

	sut, err := NewCachingResolver(ctx, cfg, nil)
	if err != nil {
		b.Fatal(err)
	}

	sut.Next(benchBackend{})

	reqs := make([]*model.Request, numDomains)
	for i := range reqs {
		reqs[i] = newRequest(fmt.Sprintf("domain%d.example.", i), dns.Type(dns.TypeA))
	}

	// warm the cache: each first Resolve is a miss that fills the cache
	for _, r := range reqs {
		if _, err := sut.Resolve(ctx, r); err != nil {
			b.Fatal(err)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			// Resolve is validated during warm-up above; the parallel loop is all
			// cache hits, so skip the error check (and a branch) on the measured path.
			// b.Fatal must not be called from RunParallel's worker goroutines anyway.
			_, _ = sut.Resolve(ctx, reqs[i%numDomains])
			i++
		}
	})
}
