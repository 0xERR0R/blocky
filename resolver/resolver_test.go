package resolver

import (
	"github.com/0xERR0R/blocky/config"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Resolver", func() {
	systemResolverBootstrap := &Bootstrap{}

	Describe("Creating resolver chain", func() {
		When("A chain of resolvers will be created", func() {
			It("should be iterable by calling 'GetNext'", func() {
				br, _ := NewBlockingResolver(config.BlockingConfig{BlockType: "zeroIP"}, nil, systemResolverBootstrap)
				cr, _ := NewClientNamesResolver(config.ClientLookupConfig{}, nil, false)
				ch := Chain(br, cr)
				c, ok := ch.(ChainedResolver)
				Expect(ok).Should(BeTrue())

				next := c.GetNext()
				Expect(next).ShouldNot(BeNil())
			})
		})
		When("'Name' is called", func() {
			It("should return resolver name", func() {
				br, _ := NewBlockingResolver(config.BlockingConfig{BlockType: "zeroIP"}, nil, systemResolverBootstrap)
				name := Name(br)
				Expect(name).Should(Equal("BlockingResolver"))
			})
		})
		When("'Name' is called on a NamedResolver", func() {
			It("should return it's custom name", func() {
				br, _ := NewBlockingResolver(config.BlockingConfig{BlockType: "zeroIP"}, nil, systemResolverBootstrap)

				cfg := config.RewriteConfig{Rewrite: map[string]string{"not": "empty"}}
				r := NewRewriterResolver(cfg, br)

				name := Name(r)
				Expect(name).Should(Equal("BlockingResolver w/ RewriterResolver"))
			})
		})
	})
})
