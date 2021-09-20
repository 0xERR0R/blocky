package resolver

import (
	"errors"

	"github.com/0xERR0R/blocky/config"

	. "github.com/0xERR0R/blocky/model"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("MetricResolver", func() {
	var (
		sut  *MetricsResolver
		m    *resolverMock
		err  error
		resp *Response
	)

	BeforeEach(func() {
		sut = NewMetricsResolver(config.PrometheusConfig{Enable: true}).(*MetricsResolver)
		m = &resolverMock{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
		sut.Next(m)
	})

	Describe("Recording prometheus metrics", func() {
		Context("Recording request metrics", func() {
			When("Request will be performed", func() {
				It("Should record metrics", func() {
					resp, err = sut.Resolve(newRequestWithClient("example.com.", dns.TypeA, "", "client"))
					Expect(err).Should(Succeed())

					cnt, err := sut.totalQueries.GetMetricWith(prometheus.Labels{"client": "client", "type": "A"})
					Expect(err).Should(Succeed())

					Expect(testutil.ToFloat64(cnt)).Should(Equal(float64(1)))
					Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
					m.AssertExpectations(GinkgoT())
				})
			})
			When("Error occurs while request processing", func() {
				BeforeEach(func() {
					m = &resolverMock{}
					m.On("Resolve", mock.Anything).Return(nil, errors.New("error"))
					sut.Next(m)
				})
				It("Error should be recorded", func() {
					resp, err = sut.Resolve(newRequestWithClient("example.com.", dns.TypeA, "", "client"))
					Expect(err).Should(HaveOccurred())

					Expect(testutil.ToFloat64(sut.totalErrors)).Should(Equal(float64(1)))
				})
			})
		})
	})

	Describe("Configuration output", func() {
		When("resolver is enabled", func() {
			It("should return configuration", func() {
				c := sut.Configuration()
				Expect(len(c) > 1).Should(BeTrue())
			})
		})
	})
})
