package metrics_test

import (
	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/metrics"
	"github.com/0xERR0R/blocky/service"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Metrics Service", func() {
	var (
		cfg        config.MetricsService
		metricsCfg config.Metrics
		sut        *Service
		err        error
	)

	BeforeEach(func() {
		cfg, err = config.WithDefaults[config.MetricsService]()
		Expect(err).Should(Succeed())

		cfg.Addrs.HTTP = config.ListenConfig{":80"}
		cfg.Addrs.HTTPS = config.ListenConfig{":443"}

		metricsCfg, err = config.WithDefaults[config.Metrics]()
		Expect(err).Should(Succeed())

		metricsCfg.Enable = true
	})

	JustBeforeEach(func() {
		sut = NewService(cfg, metricsCfg)
	})

	Describe("NewService", func() {
		When("enabled", func() {
			BeforeEach(func() {
				metricsCfg.Path = "/metrics-path"
			})

			It("uses the configured addresses", func() {
				Expect(sut.ExposeOn()).Should(ContainElements(
					Equal(service.Endpoint{Protocol: "http", AddrConf: ":80"}),
					Equal(service.Endpoint{Protocol: "https", AddrConf: ":443"}),
				))
			})

			It("uses the configured path", func() {
				Expect(sut.Router().Routes()).Should(HaveLen(1))
				Expect(sut.Router().Routes()[0].Pattern).Should(Equal("/metrics-path"))
			})
		})

		When("no addresses are configured", func() {
			BeforeEach(func() {
				cfg.Addrs = config.AllHTTPAddrs{}
			})

			It("is disabled", func() {
				Expect(*sut).Should(BeZero())
			})
		})

		When("metrics are disabled", func() {
			BeforeEach(func() {
				metricsCfg.Enable = false
			})

			It("is disabled", func() {
				Expect(*sut).Should(BeZero())
			})
		})
	})
})
