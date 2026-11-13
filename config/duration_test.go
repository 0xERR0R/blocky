package config

import (
	"math"
	"strconv"
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

		It("should parse a number without unit as minutes", func() {
			Expect(d.UnmarshalText([]byte("5"))).Should(Succeed())
			Expect(d).Should(Equal(Duration(5 * time.Minute)))
			Expect(d.UnmarshalText([]byte("-5"))).Should(Succeed())
			Expect(d).Should(Equal(Duration(-5 * time.Minute)))
		})

		It("should parse the largest number of minutes that fits", func() {
			Expect(d.UnmarshalText([]byte(strconv.FormatInt(maxMinutes, 10)))).Should(Succeed())
			Expect(d).Should(Equal(Duration(time.Duration(maxMinutes) * time.Minute)))
		})

		It("should fail if a number of minutes overflows the duration", func() {
			// would wrap around to a negative duration
			for _, in := range []string{
				strconv.FormatInt(maxMinutes+1, 10),
				strconv.FormatInt(-maxMinutes-1, 10),
				strconv.FormatInt(math.MaxInt64, 10),
			} {
				d = Duration(time.Hour)

				err := d.UnmarshalText([]byte(in))
				Expect(err).Should(MatchError(ContainSubstring("invalid duration '" + in + "'")))
				Expect(d).Should(Equal(Duration(time.Hour)))
			}
		})

		It("should fail if duration is in wrong format", func() {
			err := d.UnmarshalText([]byte("wrong"))
			Expect(err).Should(HaveOccurred())
			Expect(err).Should(MatchError("invalid duration 'wrong': time: invalid duration \"wrong\""))
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
