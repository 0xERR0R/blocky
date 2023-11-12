package parsers

import (
	"context"
	"errors"
	"fmt"

	. "github.com/0xERR0R/blocky/helpertest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ForEach", func() {
	var lines SeriesParser[string]

	BeforeEach(func() {
		lines = Lines(linesReader(
			"first",
			"second",
			"third",
		))
	})

	It("should iterate and hide io.EOF", func() {
		list := iteratorToList(func(cb func(string) error) error {
			return ForEach(context.Background(), lines, cb)
		})

		Expect(list).Should(Equal([]string{"first", "second", "third"}))
	})

	It("should return callback errors", func() {
		expectedErr := errors.New("fail")

		err := ForEach(context.Background(), lines, func(line string) error {
			return expectedErr
		})
		Expect(err).ShouldNot(Succeed())
		Expect(err).Should(MatchError(expectedErr))
		Expect(err.Error()).Should(HavePrefix("line 1: "))
	})

	It("should return parser errors", func() {
		lines := Hosts(linesReader(
			"invalid line",
		))

		err := ForEach(context.Background(), lines, func(*HostsIterator) error {
			Fail("callback should not be called")

			return nil
		})
		Expect(err).ShouldNot(Succeed())
		Expect(err.Error()).Should(HavePrefix("line 1: "))
	})

	It("should stop when context is done", func() {
		ctx, cancel := context.WithCancel(context.Background())

		err := ForEach(ctx, lines, func(line string) error {
			if ctx.Err() != nil {
				Fail("callback should not be called")
			}

			cancel()

			return nil
		})
		Expect(err).ShouldNot(Succeed())
		Expect(err).Should(MatchError(context.Canceled))
		Expect(err.Error()).Should(HavePrefix("line 1: "))
	})

	It("should not start if context is already done", func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := ForEach(ctx, lines, func(line string) error {
			Fail("callback should not be called")

			return nil
		})
		Expect(err).ShouldNot(Succeed())
		Expect(err).Should(MatchError(context.Canceled))
		Expect(err.Error()).Should(HavePrefix("line 0: "))
	})
})

var _ = Describe("ErrWithPosition", func() {
	When("err is nil", func() {
		It("returns nil", func() {
			inner := errors.New("inner")
			lines := Lines(linesReader(
				"first",
				"second",
			))

			_, err := lines.Next(context.Background())
			Expect(err).Should(Succeed())

			err = ErrWithPosition(lines, inner)
			Expect(err).ShouldNot(Succeed())
			Expect(err.Error()).Should(Equal("line 1: inner"))

			_, err = lines.Next(context.Background())
			Expect(err).Should(Succeed())

			err = ErrWithPosition(lines, inner)
			Expect(err).ShouldNot(Succeed())
			Expect(err.Error()).Should(Equal("line 2: inner"))
		})
	})

	When("err is nil", func() {
		It("returns nil", func() {
			err := ErrWithPosition[any](nil, nil)
			Expect(err).Should(Succeed())
		})
	})
})

var _ = Describe("NonResumableError", func() {
	Describe("IsNonResumableErr", func() {
		It("should return the inner error", func() {
			inner := errors.New("inner")
			Expect(IsNonResumableErr(inner)).Should(BeFalse())

			err := NewNonResumableError(inner)
			Expect(IsNonResumableErr(err)).Should(BeTrue())
		})
	})

	Describe("Error", func() {
		It("should return error message", func() {
			inner := errors.New("inner")

			err := NewNonResumableError(inner)
			Expect(err.Error()).Should(Equal("non resumable parse error: inner"))
		})
	})

	Describe("Unwrap", func() {
		It("should return the inner error", func() {
			inner := errors.New("inner")

			err := NewNonResumableError(inner)
			Expect(errors.Unwrap(err)).Should(Equal(inner))
			Expect(errors.Is(err, inner)).Should(BeTrue())
		})
	})
})

func iteratorToList[T any](forEach func(func(T) error) error) []T {
	var res []T

	err := forEach(func(t T) error {
		res = append(res, t)

		return nil
	})
	Expect(err).Should(Succeed())

	return res
}

type mockParser[T any] struct{ MockCallSequence[T] }

func newMockParser[T any](driver func(chan<- T, chan<- error)) SeriesParser[T] {
	return &mockParser[T]{NewMockCallSequence(driver)}
}

func (m *mockParser[T]) Next(ctx context.Context) (_ T, rerr error) {
	defer func() {
		if rerr != nil && IsNonResumableErr(rerr) {
			m.Close()
		}
	}()

	if err := ctx.Err(); err != nil {
		var zero T

		return zero, NewNonResumableError(err)
	}

	return m.Call()
}

func (m *mockParser[T]) Position() string {
	return fmt.Sprintf("call %d", m.CallCount())
}
