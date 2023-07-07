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

	Describe("IsAboveZero", func() {
		It("should be false for zero", func() {
			Expect(d.IsAboveZero()).Should(BeFalse())
			Expect(Duration(0).IsAboveZero()).Should(BeFalse())
		})

		It("should be false for negative", func() {
			Expect(Duration(-1).IsAboveZero()).Should(BeFalse())
		})

		It("should be true for positive", func() {
			Expect(Duration(1).IsAboveZero()).Should(BeTrue())
		})
	})

	Describe("SecondsU32", func() {
		It("should return the seconds", func() {
			Expect(Duration(time.Minute).SecondsU32()).Should(Equal(uint32(60)))
			Expect(Duration(time.Hour).SecondsU32()).Should(Equal(uint32(3600)))
		})
	})
})
