package resolver

import (
	"blocky/config"

	"github.com/go-chi/chi"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Resolver", func() {
	Describe("Creating resolver chain", func() {
		When("A chain of resolvers will be created", func() {
			It("should be iterable by calling 'GetNext'", func() {
				ch := Chain(NewBlockingResolver(chi.NewRouter(),
					config.BlockingConfig{}), NewClientNamesResolver(config.ClientLookupConfig{}))
				c, ok := ch.(ChainedResolver)
				Expect(ok).Should(BeTrue())

				next := c.GetNext()
				Expect(next).ShouldNot(BeNil())
			})
		})
		When("'Name' will be called", func() {
			It("should return resolver name", func() {
				name := Name(NewBlockingResolver(chi.NewRouter(), config.BlockingConfig{}))
				Expect(name).Should(Equal("BlockingResolver"))
			})
		})
	})
})
