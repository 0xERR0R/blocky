package config

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Duration", func() {
	var d Duration

	BeforeEach(func() {
		var zero Duration

		d = zero
	})

	Describe("UnmarshalText", func() {
		It("should parse duration with unit", func() {
			err := d.UnmarshalText([]byte("1m20s"))
			Expect(err).Should(Succeed())
			Expect(d).Should(Equal(Duration(80 * time.Second)))
			Expect(d.String()).Should(Equal("1 minute 20 seconds"))
		})

		It("should fail if duration is in wrong format", func() {
			err := d.UnmarshalText([]byte("wrong"))
			Expect(err).Should(HaveOccurred())
			Expect(err).Should(MatchError("time: invalid duration \"wrong\""))
		})
	})

	Describe("IsZero", func() {
		It("should be true for zero", func() {
			Expect(d.IsZero()).Should(BeTrue())
			Expect(Duration(0).IsZero()).Should(BeTrue())
		})

		It("should be false for non-zero", func() {
			Expect(Duration(time.Second).IsZero()).Should(BeFalse())
		})
	})
})
