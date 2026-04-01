package util

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Pipeline", func() {
	Describe("NewPipeline", func() {
		When("single producer and single consumer", func() {
			It("should deliver all items from producer to consumer", func() {
				ctx := context.Background()
				p := NewPipeline[int](ctx, 10, nil)

				p.GoProduce(func(ctx context.Context, ch chan<- int) error {
					for i := 0; i < 5; i++ {
						ch <- i
					}

					return nil
				})

				var received []int

				p.GoConsume(func(ctx context.Context, ch <-chan int) error {
					for val := range ch {
						received = append(received, val)
					}

					return nil
				})

				err := p.Wait()
				Expect(err).Should(Succeed())
				Expect(received).Should(Equal([]int{0, 1, 2, 3, 4}))
			})
		})
	})
})
