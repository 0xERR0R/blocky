package util

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// Pipeline implements a multi-producer, single-consumer pattern
// with optional shared concurrency limiting for producers.
type Pipeline[T any] struct {
	ctx       context.Context
	items     chan T
	sem       chan struct{} // nil = no limit
	producers sync.WaitGroup
	consumers sync.WaitGroup
	mu        sync.Mutex
	errs      []error
	closeOnce sync.Once
}

// NewPipeline creates a new Pipeline with the given buffer capacity and optional semaphore.
// If sem is nil, producers are not concurrency-limited.
// If sem is non-nil, it is used as a shared semaphore across all producers (possibly across multiple Pipelines).
func NewPipeline[T any](ctx context.Context, bufferCap int, sem chan struct{}) *Pipeline[T] {
	return &Pipeline[T]{
		ctx:   ctx,
		items: make(chan T, bufferCap),
		sem:   sem,
	}
}

func (p *Pipeline[T]) saveErr(err error) {
	if err == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.errs = append(p.errs, err)
}

// GoProduce starts a producer goroutine. The producer function sends items to the channel.
// If a semaphore was provided, the producer acquires a slot before running.
func (p *Pipeline[T]) GoProduce(fn func(context.Context, chan<- T) error) {
	p.producers.Add(1)

	go func() {
		defer p.producers.Done()

		defer func() {
			if r := recover(); r != nil {
				p.saveErr(fmt.Errorf("producer panic: %v", r))
			}
		}()

		if p.sem != nil {
			select {
			case p.sem <- struct{}{}:
				defer func() { <-p.sem }()
			case <-p.ctx.Done():
				p.saveErr(p.ctx.Err())

				return
			}
		}

		p.saveErr(fn(p.ctx, p.items))
	}()
}

// GoConsume starts a consumer goroutine. The consumer function receives items from the channel.
// The channel is closed after all producers finish and Wait is called.
func (p *Pipeline[T]) GoConsume(fn func(context.Context, <-chan T) error) {
	p.consumers.Add(1)

	go func() {
		defer p.consumers.Done()

		defer func() {
			if r := recover(); r != nil {
				p.saveErr(fmt.Errorf("consumer panic: %v", r))
			}
		}()

		p.saveErr(fn(p.ctx, p.items))
	}()
}

func (p *Pipeline[T]) closeItems() {
	p.closeOnce.Do(func() {
		close(p.items)
	})
}

// Wait waits for all producers to finish, closes the items channel,
// then waits for all consumers to finish. Returns all collected errors.
func (p *Pipeline[T]) Wait() error {
	p.producers.Wait()
	p.closeItems()
	p.consumers.Wait()

	p.mu.Lock()
	defer p.mu.Unlock()

	return errors.Join(p.errs...)
}

// Close is a safety-net method that ensures producers are waited on, the channel is closed,
// and consumers complete. Unlike Wait, it does not return errors.
// It is safe to call both Wait and Close (channel close is protected by sync.Once).
func (p *Pipeline[T]) Close() {
	p.producers.Wait()
	p.closeItems()
	p.consumers.Wait()
}
