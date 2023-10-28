package resolver

import (
	"github.com/0xERR0R/blocky/config"
	"github.com/creasty/defaults"

	. "github.com/0xERR0R/blocky/model"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("EcsResolver", func() {
	var (
		sut        *EcsResolver
		sutConfig  config.EcsConfig
		m          *mockResolver
		mockAnswer *dns.Msg
		err        error
	)

	Describe("Type", func() {
		It("follows conventions", func() {
			expectValidResolverType(sut)
		})
	})

	BeforeEach(func() {
		mockAnswer = new(dns.Msg)
	})

	JustBeforeEach(func() {
		if m == nil {
			m = &mockResolver{}
			m.On("Resolve", mock.Anything).Return(&Response{
				Res:    mockAnswer,
				RType:  ResponseTypeCUSTOMDNS,
				Reason: "Test",
			}, nil)
		}

		sut = NewEcsResolver(sutConfig).(*EcsResolver)
		sut.Next(m)
	})

	When("ecs is disabled", func() {
		BeforeEach(func() {
			err = defaults.Set(&sutConfig)
			Expect(err).ShouldNot(HaveOccurred())
		})
		Describe("IsEnabled", func() {
			It("is false", func() {
				Expect(sut.IsEnabled()).Should(BeFalse())
			})
		})
	})

	When("ecs is disabled", func() {
		BeforeEach(func() {
			err = defaults.Set(&sutConfig)
			Expect(err).ShouldNot(HaveOccurred())

			sutConfig.UseEcsAsClient = true
		})
		Describe("IsEnabled", func() {
			It("is true", func() {
				Expect(sut.IsEnabled()).Should(BeTrue())
			})
		})
	})
})

// func getDefaultConfig() *config.EcsConfig {
// 	var res config.EcsConfig
// 	err := defaults.Set(&res)

// 	Expect(err).Should(Succeed())

// 	return &res
// }
