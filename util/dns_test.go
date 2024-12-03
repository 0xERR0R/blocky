package util

import (
	"math"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("EDNS0 utils", func() {
	DescribeTable("ToTTL",
		func(input interface{}, expected int) {
			res := uint32(0)
			switch it := input.(type) {
			case uint32:
				res = ToTTL(it)
			case int:
				res = ToTTL(it)
			case int64:
				res = ToTTL(it)
			case time.Duration:
				res = ToTTL(it)
			default:
				Fail("unsupported type")
			}

			Expect(ToTTL(res)).Should(Equal(uint32(expected)))
		},
		Entry("should return 0 for negative input", -1, 0),
		Entry("should return uint32 for uint32 input", uint32(1), 1),
		Entry("should return uint32 for int input", 1, 1),
		Entry("should return uint32 for int64 input", int64(1), 1),
		Entry("should return seconds for time.Duration input", time.Second, 1),
		Entry("should return math.MaxUint32 for too large input", int64(math.MaxUint32)+1, math.MaxUint32),
	)
})
