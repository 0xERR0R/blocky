package api

import (
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/service"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("API Service", func() {
	var (
		cfg config.APIService
		sut *Service
		err error
	)

	BeforeEach(func() {
		cfg, err = config.WithDefaults[config.APIService]()
		Expect(err).Should(Succeed())

		cfg.Addrs.HTTP = config.ListenConfig{":80"}
		cfg.Addrs.HTTPS = config.ListenConfig{":443"}
	})

	JustBeforeEach(func() {
		sut = NewService(cfg, nil)
	})

	Describe("NewService", func() {
		When("enabled", func() {
			It("uses the configured addresses", func() {
				Expect(sut.ExposeOn()).Should(ContainElements(
					Equal(service.Endpoint{Protocol: "http", AddrConf: ":80"}),
					Equal(service.Endpoint{Protocol: "https", AddrConf: ":443"}),
				))
			})

			It("sets up routes", func() {
				Expect(sut.Router().Routes()).ShouldNot(BeEmpty())
			})
		})
	})
})
