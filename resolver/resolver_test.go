package resolver

import (
	"github.com/0xERR0R/blocky/model"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type NoOpChainedResolver struct {
	NextResolver
}

func (r NoOpChainedResolver) Resolve(req *model.Request) (*model.Response, error) {
	return r.next.Resolve(req)
}

func (r NoOpChainedResolver) Configuration() []string {
	return nil
}

var _ = Describe("Resolver", func() {
	Describe("ChainBuilder", func() {
		var (
			beg ChainedResolver
			mid ChainedResolver
			end Resolver
			cb  *ChainBuilder
			ch  Resolver
			err error
		)

		BeforeEach(func() {
			beg = &NoOpChainedResolver{}
			mid = &NoOpChainedResolver{}
			end = NewNoOpResolver()
		})

		Describe("successful build", func() {
			AfterEach(func() {
				Expect(ch).Should(Equal(beg))
				Expect(beg.GetNext()).Should(Equal(mid))
				Expect(mid.GetNext()).Should(Equal(end))
			})

			When("complete", func() {
				BeforeEach(func() {
					cb = NewChainBuilder(beg, mid)
					Expect(cb).ShouldNot(BeNil())

					ch, err = cb.End(end)
					Expect(err).Should(Succeed())
					Expect(ch).ShouldNot(BeNil())
				})

				It("should be iterable by calling 'GetNext'", func() {})

				It("should not be reusable", func() {
					defer func() {
						Expect(recover()).ShouldNot(BeNil())
					}()

					cb.Next(&NoOpChainedResolver{})
				})
			})

			When("first is nil", func() {
				It("should complete", func() {
					ch, err = NewChainBuilder(nil, beg, mid).End(end)
					Expect(err).Should(Succeed())
					Expect(ch).ShouldNot(BeNil())
				})
			})

			When("first two are nil", func() {
				It("should complete", func() {
					ch, err = NewChainBuilder(nil, nil, beg, mid).End(end)
					Expect(err).Should(Succeed())
					Expect(ch).ShouldNot(BeNil())
				})
			})

			When("some are nil", func() {
				It("should complete", func() {
					ch, err = NewChainBuilder(nil, beg, nil, mid, nil).End(end)
					Expect(err).Should(Succeed())
					Expect(ch).ShouldNot(BeNil())
				})
			})
		})

		When("given no resolvers", func() {
			It("should be nil", func() {
				cb := NewChainBuilder(nil)
				Expect(cb).Should(BeNil())
			})

			It("should complete", func() {
				cb := NewChainBuilder(nil)
				Expect(cb).Should(BeNil())

				ch, err := cb.End(NewNoOpResolver())
				Expect(err).Should(Succeed())
				Expect(ch).ShouldNot(BeNil())
			})
		})

		When("ended with nil", func() {
			It("should fail", func() {
				cb := NewChainBuilder(nil, nil)
				Expect(cb).Should(BeNil())

				_, err := cb.End(nil)
				Expect(err).ShouldNot(BeNil())
			})
		})

		When("ended with a ChainedResolver", func() {
			It("should fail", func() {
				cb := NewChainBuilder(nil, nil)
				Expect(cb).Should(BeNil())

				_, err := cb.End(&NoOpChainedResolver{})
				Expect(err).ShouldNot(BeNil())
			})
		})
	})

	When("'Name' is called", func() {
		It("should return resolver name", func() {
			name := Name(NewNoOpResolver())
			Expect(name).Should(Equal("NoOpResolver"))
		})
		When("'Name' is called on a NamedResolver", func() {
			It("should return it's custom name", func() {
				br, _ := NewBlockingResolver(config.BlockingConfig{BlockType: "zeroIP"}, nil)

				cfg := config.RewriteConfig{Rewrite: map[string]string{"not": "empty"}}
				r := NewRewriterResolver(cfg, br)

				name := Name(r)
				Expect(name).Should(Equal("BlockingResolver w/ RewriterResolver"))
			})
		})
	})
})
