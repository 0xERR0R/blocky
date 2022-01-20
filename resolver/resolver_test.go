package resolver

import (
	"github.com/0xERR0R/blocky/config"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Resolver", func() {
	Describe("Creating resolver chain", func() {
		When("A chain of resolvers will be created", func() {
			It("should be iterable by calling 'GetNext'", func() {
				br, _ := NewBlockingResolver(config.BlockingConfig{BlockType: "zeroIP"}, nil)
				ch := Chain(br, NewClientNamesResolver(config.ClientLookupConfig{}))
				c, ok := ch.(ChainedResolver)
				Expect(ok).Should(BeTrue())

				next := c.GetNext()
				Expect(next).ShouldNot(BeNil())
			})
		})
		When("'Name' will be called", func() {
			It("should return resolver name", func() {
				br, _ := NewBlockingResolver(config.BlockingConfig{BlockType: "zeroIP"}, nil)
				name := Name(br)
				Expect(name).Should(Equal("BlockingResolver"))
			})
		})
	})
})
