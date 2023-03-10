package config

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Duration", func() {
	var d Duration

	It("should parse duration with unit", func() {
		err := d.UnmarshalText([]byte("1m20s"))
		Expect(err).Should(Succeed())
		Expect(d).Should(Equal(NewDuration(80 * time.Second)))
		Expect(d.String()).Should(Equal("1 minute 20 seconds"))
	})

	It("should fail if duration is in wrong format", func() {
		err := d.UnmarshalText([]byte("wrong"))
		Expect(err).Should(HaveOccurred())
		Expect(err).Should(MatchError("time: invalid duration \"wrong\""))
	})
})
