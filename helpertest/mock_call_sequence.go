package helpertest

import (
	"context"
	"fmt"
	"sync"
	"time"
)

const mockCallTimeout = 2 * time.Second

type MockCallSequence[T any] struct {
	driver    func(chan<- T, chan<- error)
	res       chan T
	err       chan error
	callCount uint
	initOnce  sync.Once
	closeOnce sync.Once
}

func NewMockCallSequence[T any](driver func(chan<- T, chan<- error)) MockCallSequence[T] {
	return MockCallSequence[T]{
		driver: driver,
	}
}

func (m *MockCallSequence[T]) Call() (T, error) {
	m.callCount++

	m.initOnce.Do(func() {
		m.res = make(chan T)
		m.err = make(chan error)

		// This goroutine never stops
		go func() {
			defer m.Close()

			m.driver(m.res, m.err)
		}()
	})

	ctx, cancel := context.WithTimeout(context.Background(), mockCallTimeout)
	defer cancel()

	select {
	case t, ok := <-m.res:
		if !ok {
			break
		}

		return t, nil

	case err, ok := <-m.err:
		if !ok {
			break
		}

		var zero T

		return zero, err

	case <-ctx.Done():
		panic(fmt.Sprintf("mock call sequence driver timed-out on call %d", m.CallCount()))
	}

	panic("mock call sequence called after driver returned (or sequence Close was called explicitly)")
}

func (m *MockCallSequence[T]) CallCount() uint {
	return m.callCount
}

func (m *MockCallSequence[T]) Close() {
	m.closeOnce.Do(func() {
		close(m.res)
		close(m.err)
	})
}
