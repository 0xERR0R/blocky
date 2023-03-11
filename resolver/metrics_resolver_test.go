package resolver

import (
	"errors"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"

	. "github.com/0xERR0R/blocky/helpertest"
	. "github.com/0xERR0R/blocky/model"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("MetricResolver", func() {
	var (
		sut *MetricsResolver
		m   *mockResolver
	)

	Describe("Type", func() {
		It("follows conventions", func() {
			expectValidResolverType(sut)
		})
	})

	BeforeEach(func() {
		sut = NewMetricsResolver(config.MetricsConfig{Enable: true}).(*MetricsResolver)
		m = &mockResolver{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
		sut.Next(m)
	})

	Describe("IsEnabled", func() {
		It("is true", func() {
			Expect(sut.IsEnabled()).Should(BeTrue())
		})
	})

	Describe("LogConfig", func() {
		It("should log something", func() {
			logger, hook := log.NewMockEntry()

			sut.LogConfig(logger)

			Expect(hook.Calls).ShouldNot(BeEmpty())
		})
	})

	Describe("Recording prometheus metrics", func() {
		Context("Recording request metrics", func() {
			When("Request will be performed", func() {
				It("Should record metrics", func() {
					Expect(sut.Resolve(newRequestWithClient("example.com.", A, "", "client"))).
						Should(
							SatisfyAll(
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))

					cnt, err := sut.totalQueries.GetMetricWith(prometheus.Labels{"client": "client", "type": "A"})
					Expect(err).Should(Succeed())

					Expect(testutil.ToFloat64(cnt)).Should(BeNumerically("==", 1))
					m.AssertExpectations(GinkgoT())
				})
			})
			When("Error occurs while request processing", func() {
				BeforeEach(func() {
					m = &mockResolver{}
					m.On("Resolve", mock.Anything).Return(nil, errors.New("error"))
					sut.Next(m)
				})
				It("Error should be recorded", func() {
					_, err := sut.Resolve(newRequestWithClient("example.com.", A, "", "client"))

					Expect(err).Should(HaveOccurred())

					Expect(testutil.ToFloat64(sut.totalErrors)).Should(BeNumerically("==", 1))
				})
			})
		})
	})
})
