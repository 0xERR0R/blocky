package resolver

import (
	"blocky/util"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("StatsResolver", func() {
	var (
		sut ChainedResolver
		m   *resolverMock
	)
	BeforeEach(func() {
		sut = NewStatsResolver()
		m = &resolverMock{}
		resp, _ := util.NewMsgWithAnswer("example.com.", 300, dns.TypeA, "123.122.121.120")
		m.On("Resolve", mock.Anything).Return(&Response{Res: resp, Reason: "reason"}, nil)
		sut.Next(m)
	})

	Describe("Gathering staticsics", func() {
		When("Request will be processed", func() {
			It("should gather staticsics", func() {
				_, err := sut.Resolve(newRequestWithClient("example.com.", dns.TypeA, "192.168.178.33", "client1"))
				Expect(err).Should(Succeed())
				m.AssertExpectations(GinkgoT())

				sut.(*StatsResolver).printStats()
			})
		})
	})

	Describe("Configuration output", func() {
		It("should return configuration", func() {
			c := sut.Configuration()
			Expect(len(c) > 1).Should(BeTrue())
		})
	})
})
