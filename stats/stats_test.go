package stats

import (
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Config", func() {
	var (
		mockTime string
	)
	BeforeEach(func() {
		now = func() time.Time {
			t, _ := time.Parse("20060102_1505", mockTime)
			return t
		}
	})
	Describe("Put value into stats aggregator", func() {
		When("Put exceeds max of 3", func() {
			It("should return only 3 entries", func() {
				mockTime = "20200101_0101"
				s := NewAggregatorWithMax("test", 3)

				s.Put("a2")
				s.Put("a1")
				s.Put("a2")
				s.Put("a3")
				s.Put("a1")
				s.Put("a1")
				s.Put("a4")
				s.Put("a5")
				s.Put("a2")
				s.Put("a6")
				s.Put("a1")
				s.Put("a6")
				s.Put("a1")

				// change hour
				mockTime = "20200101_0201"

				s.Put("a1")
				res := s.AggregateResult()

				Expect(res).Should(HaveLen(3))
				Expect(res["a1"]).Should(Equal(5))
				Expect(res["a2"]).Should(Equal(3))
				Expect(res["a6"]).Should(Equal(2))
			})
		})
		When("Put under max", func() {
			It("should return correct value", func() {
				mockTime = "20200105_0101"
				s := NewAggregator("test")

				s.Put("a2")
				s.Put("a1")
				s.Put("a2")
				s.Put("a3")
				s.Put("a2")
				s.Put("a2")
				s.Put("a2")

				// change hour
				mockTime = "20200105_0201"

				s.Put("a1")

				res := s.AggregateResult()

				Expect(res).Should(HaveLen(3))
				Expect(res["a1"]).Should(Equal(1))
				Expect(res["a2"]).Should(Equal(5))
				Expect(res["a3"]).Should(Equal(1))
			})
		})
	})
	Describe("Aggregate multiple hours", func() {
		When("Put is called through several hours", func() {
			It("should aggregate result", func() {
				mockTime = "20200102_0101"
				s := NewAggregatorWithMax("test", 3)

				s.Put("a2")
				s.Put("a1")
				s.Put("a2")
				s.Put("a3")
				s.Put("a1")
				s.Put("a1")
				s.Put("a4")
				s.Put("a5")
				s.Put("a2")
				s.Put("a6")
				s.Put("a1")
				s.Put("a6")
				s.Put("a1")

				// change hour
				mockTime = "20200102_0201"

				s.Put("a1")

				// change hour
				mockTime = "20200102_0301"

				s.Put("a2")
				s.Put("a1")

				// change hour
				mockTime = "20200102_0401"

				res := s.AggregateResult()
				Expect(res).Should(HaveLen(3))
				Expect(res["a1"]).Should(Equal(7))
				Expect(res["a2"]).Should(Equal(4))
				Expect(res["a6"]).Should(Equal(2))
			})
		})
	})
	Describe("Aggregate over 24h", func() {
		When("Put is called in a time range over 24h", func() {
			It("should aggregate only last 24h", func() {
				mockTime = "20200103_0101"
				s := NewAggregatorWithMax("test", 3)

				s.Put("a1")
				s.Put("a2")

				// change hour
				mockTime = "20200103_0201"

				s.Put("a2")
				s.Put("a3")

				// change hour
				mockTime = "20200103_0301"

				s.Put("a3")
				s.Put("a4")
				s.Put("a5")

				// change day
				mockTime = "20200104_0101"

				res := s.AggregateResult()

				Expect(res).Should(HaveLen(3))
				Expect(res["a3"]).Should(Equal(2))
				Expect(res["a4"]).Should(Equal(1))
				Expect(res["a5"]).Should(Equal(1))
			})
		})
	})
	Describe("Empty aggregation", func() {
		When("parameter is empty", func() {
			It("should be ignored", func() {
				mockTime = "20200104_0101"
				s := NewAggregator("test")

				s.Put("")
				s.Put("a1")

				// change hour
				mockTime = "20200104_0201"

				res := s.AggregateResult()

				Expect(res).Should(HaveLen(1))
			})
		})
	})
})

func Test_Put_Empty(t *testing.T) {

}
