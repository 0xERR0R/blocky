package util

import (
	"context"
	"errors"
	"sync"
	"time"

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

		When("multiple producers and single consumer", func() {
			It("should deliver all items from all producers", func() {
				ctx := context.Background()
				p := NewPipeline[int](ctx, 10, nil)

				for i := range 3 {
					start := i * 10
					p.GoProduce(func(ctx context.Context, ch chan<- int) error {
						for j := range 3 {
							ch <- start + j
						}

						return nil
					})
				}

				var (
					mu       sync.Mutex
					received []int
				)

				p.GoConsume(func(ctx context.Context, ch <-chan int) error {
					for val := range ch {
						mu.Lock()
						received = append(received, val)
						mu.Unlock()
					}

					return nil
				})

				err := p.Wait()
				Expect(err).Should(Succeed())
				Expect(received).Should(HaveLen(9))
				Expect(received).Should(ContainElements(0, 1, 2, 10, 11, 12, 20, 21, 22))
			})
		})

		When("concurrency limiting via semaphore", func() {
			It("should respect the semaphore capacity", func() {
				ctx := context.Background()
				sem := make(chan struct{}, 2)
				p := NewPipeline[int](ctx, 100, sem)

				var (
					mu         sync.Mutex
					maxRunning int
					running    int
				)

				for range 5 {
					p.GoProduce(func(ctx context.Context, ch chan<- int) error {
						mu.Lock()
						running++
						if running > maxRunning {
							maxRunning = running
						}
						mu.Unlock()

						time.Sleep(50 * time.Millisecond)

						mu.Lock()
						running--
						mu.Unlock()

						ch <- 1

						return nil
					})
				}

				p.GoConsume(func(ctx context.Context, ch <-chan int) error {
					for range ch {
					}

					return nil
				})

				err := p.Wait()
				Expect(err).Should(Succeed())

				mu.Lock()
				Expect(maxRunning).Should(BeNumerically("<=", 2))
				mu.Unlock()
			})
		})

		When("producers return errors", func() {
			It("should collect and return all errors", func() {
				ctx := context.Background()
				p := NewPipeline[int](ctx, 10, nil)

				p.GoProduce(func(ctx context.Context, ch chan<- int) error {
					return errors.New("producer error 1")
				})

				p.GoProduce(func(ctx context.Context, ch chan<- int) error {
					return errors.New("producer error 2")
				})

				p.GoConsume(func(ctx context.Context, ch <-chan int) error {
					for range ch {
					}

					return nil
				})

				err := p.Wait()
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("producer error"))
			})
		})

		When("consumer returns error", func() {
			It("should include consumer error in result", func() {
				ctx := context.Background()
				p := NewPipeline[int](ctx, 10, nil)

				p.GoProduce(func(ctx context.Context, ch chan<- int) error {
					ch <- 1

					return nil
				})

				p.GoConsume(func(ctx context.Context, ch <-chan int) error {
					for range ch {
					}

					return errors.New("consumer error")
				})

				err := p.Wait()
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("consumer error"))
			})
		})

		When("context is cancelled before semaphore acquire", func() {
			It("should return context error", func() {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()

				sem := make(chan struct{}, 1)
				sem <- struct{}{} // fill so next acquire blocks, forcing cancellation path
				p := NewPipeline[int](ctx, 10, sem)

				p.GoProduce(func(ctx context.Context, ch chan<- int) error {
					return nil
				})

				p.GoConsume(func(ctx context.Context, ch <-chan int) error {
					for range ch {
					}

					return nil
				})

				err := p.Wait()
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("context canceled"))
			})
		})

		When("producer panics", func() {
			It("should recover and return panic as error", func() {
				ctx := context.Background()
				p := NewPipeline[int](ctx, 10, nil)

				p.GoProduce(func(ctx context.Context, ch chan<- int) error {
					panic("producer exploded")
				})

				p.GoConsume(func(ctx context.Context, ch <-chan int) error {
					for range ch {
					}

					return nil
				})

				err := p.Wait()
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("producer panic: producer exploded"))
			})
		})

		When("consumer panics", func() {
			It("should recover and return panic as error", func() {
				ctx := context.Background()
				p := NewPipeline[int](ctx, 10, nil)

				p.GoProduce(func(ctx context.Context, ch chan<- int) error {
					ch <- 1

					return nil
				})

				p.GoConsume(func(ctx context.Context, ch <-chan int) error {
					panic("consumer exploded")
				})

				err := p.Wait()
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("consumer panic: consumer exploded"))
			})
		})

		When("no producers are added", func() {
			It("should return nil from Wait", func() {
				ctx := context.Background()
				p := NewPipeline[int](ctx, 10, nil)

				p.GoConsume(func(ctx context.Context, ch <-chan int) error {
					for range ch {
					}

					return nil
				})

				err := p.Wait()
				Expect(err).Should(Succeed())
			})
		})

		When("both Wait and Close are called", func() {
			It("should not panic", func() {
				ctx := context.Background()
				p := NewPipeline[int](ctx, 10, nil)

				p.GoProduce(func(ctx context.Context, ch chan<- int) error {
					ch <- 1

					return nil
				})

				p.GoConsume(func(ctx context.Context, ch <-chan int) error {
					for range ch {
					}

					return nil
				})

				err := p.Wait()
				Expect(err).Should(Succeed())

				Expect(func() { p.Close() }).ShouldNot(Panic())
			})
		})
	})
})
