package config

import (
	"github.com/0xERR0R/blocky/log"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("StatisticsConfig", func() {
	var cfg Statistics

	BeforeEach(func() {
		cfg = Statistics{Enable: true}
	})

	Describe("IsEnabled", func() {
		It("is true when enabled", func() {
			Expect(cfg.IsEnabled()).Should(BeTrue())
		})

		It("is false when disabled", func() {
			cfg = Statistics{}
			Expect(cfg.IsEnabled()).Should(BeFalse())
		})
	})

	Describe("LogConfig", func() {
		It("logs the enabled state", func() {
			lgr, rec := log.NewRecorder()

			cfg.LogConfig(lgr)

			Expect(rec.Records()).ShouldNot(BeEmpty())
		})
	})
})
