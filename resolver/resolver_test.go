package resolver

import (
	"strings"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/sirupsen/logrus"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var systemResolverBootstrap = &Bootstrap{}

var _ = Describe("Resolver", func() {
	Describe("Chains", func() {
		var (
			r1 ChainedResolver
			r2 ChainedResolver
			r3 ChainedResolver
			r4 Resolver
		)

		BeforeEach(func() {
			r1 = &mockResolver{}
			r2 = &mockResolver{}
			r3 = &mockResolver{}
			r4 = &NoOpResolver{}
		})

		Describe("Chain", func() {
			It("should create a chain iterable using `GetNext`", func() {
				ch := Chain(r1, r2, r3, r4)
				Expect(ch).ShouldNot(BeNil())
				Expect(ch).Should(Equal(r1))
				Expect(r1.GetNext()).Should(Equal(r2))
				Expect(r2.GetNext()).Should(Equal(r3))
				Expect(r3.GetNext()).Should(Equal(r4))
			})

			It("should not link a final ChainedResolver", func() {
				ch := Chain(r1, r2)
				Expect(ch).ShouldNot(BeNil())

				Expect(r1.GetNext()).Should(Equal(r2))
				Expect(r2.GetNext()).Should(BeNil())
			})
		})

		Describe("ForEach", func() {
			It("should iterate on all resolvers in the chain", func() {
				ch := Chain(r1, r2, r3, r4)
				Expect(ch).ShouldNot(BeNil())

				var itResult []Resolver

				ForEach(ch, func(r Resolver) {
					itResult = append(itResult, r)
				})

				Expect(itResult).ShouldNot(BeEmpty())
				Expect(itResult).Should(Equal([]Resolver{r1, r2, r3, r4}))
			})
		})

		Describe("LogResolverConfig", func() {
			It("should call the resolver's `LogConfig`", func() {
				logger := logrus.NewEntry(log.Log())

				m := &mockResolver{}
				m.On("IsEnabled").Return(true)
				m.On("LogConfig")

				LogResolverConfig(m, logger)

				m.AssertExpectations(GinkgoT())
			})

			When("the resolver is disabled", func() {
				It("should not call the resolver's `LogConfig`", func() {
					logger := logrus.NewEntry(log.Log())

					m := &mockResolver{}
					m.On("IsEnabled").Return(false)

					LogResolverConfig(m, logger)

					m.AssertExpectations(GinkgoT())
				})
			})
		})
	})

	Describe("Name", func() {
		When("'Name' is called", func() {
			It("should return resolver name", func() {
				br, _ := NewBlockingResolver(config.BlockingConfig{BlockType: "zeroIP"}, nil, systemResolverBootstrap)
				name := Name(br)
				Expect(name).Should(Equal("blocking"))
			})
		})
		When("'Name' is called on a NamedResolver", func() {
			It("should return its custom name", func() {
				br, _ := NewBlockingResolver(config.BlockingConfig{BlockType: "zeroIP"}, nil, systemResolverBootstrap)

				cfg := config.RewriterConfig{Rewrite: map[string]string{"not": "empty"}}
				r := NewRewriterResolver(cfg, br)

				name := Name(r)
				Expect(name).Should(Equal("blocking w/ rewrite"))
			})
		})
	})
})

func expectValidResolverType(sut Resolver) {
	By("it must not contain spaces", func() {
		Expect(sut.Type()).ShouldNot(ContainSubstring(" "))
	})
	By("it must be lower case", func() {
		Expect(sut.Type()).Should(Equal(strings.ToLower(sut.Type())))
	})
	By("it must not contain 'resolver'", func() {
		Expect(sut.Type()).ShouldNot(ContainSubstring("resolver"))
	})
}
