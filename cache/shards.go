package cache

import "runtime"

const (
	// shardsPerCPU is the per-core shard multiplier. Sharding's benefit scales with
	// parallelism, so the shard count tracks GOMAXPROCS; the multiplier adds collision
	// headroom. It is bounded (not maximized) because more shards loosen the global-LRU
	// approximation and can lower hit rate. Tuned from the expiration-cache
	// BenchmarkGetParallel sweep.
	shardsPerCPU = 2

	// maxShards caps the shard count so high core counts don't fragment small caches
	// into near-empty shards.
	maxShards = 32
)

// ShardCount returns the default number of LRU shards for an in-memory cache:
// shardsPerCPU per available CPU (GOMAXPROCS), capped at maxShards. A single-CPU host
// returns 1 — it has no lock contention, so it keeps a single LRU identical to the
// unsharded cache. The expiration cache rounds this up to a power of two.
func ShardCount() uint {
	procs := runtime.GOMAXPROCS(0)
	if procs <= 1 {
		return 1
	}

	n := min(procs*shardsPerCPU, maxShards)

	return uint(n)
}
