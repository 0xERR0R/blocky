package cache

import (
	"runtime"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ShardCount", func() {
	It("returns 1 on a single CPU", func() {
		prev := runtime.GOMAXPROCS(1)
		defer runtime.GOMAXPROCS(prev)

		Expect(ShardCount()).Should(Equal(uint(1)))
	})

	It("scales by the per-CPU multiplier", func() {
		prev := runtime.GOMAXPROCS(2)
		defer runtime.GOMAXPROCS(prev)

		Expect(ShardCount()).Should(Equal(uint(2 * shardsPerCPU)))
	})

	It("never exceeds the cap", func() {
		prev := runtime.GOMAXPROCS(maxShards + 8)
		defer runtime.GOMAXPROCS(prev)

		Expect(ShardCount()).Should(Equal(uint(maxShards)))
	})
})
