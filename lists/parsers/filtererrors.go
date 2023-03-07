package parsers

import (
	"context"
	"errors"
)

// NoErrorLimit can be used to continue parsing until EOF.
const NoErrorLimit = -1

var ErrTooManyErrors = errors.New("too many parse errors")

type FilteredSeriesParser[T any] interface {
	SeriesParser[T]

	// OnErr registers a callback invoked for each error encountered.
	OnErr(func(error))
}

// AllowErrors returns a parser that wraps `inner` and tries to continue parsing.
//
// After `n` errors, it returns any error `inner` does.
func FilterErrors[T any](inner SeriesParser[T], filter func(error) error) FilteredSeriesParser[T] {
	return newErrorFilter(inner, filter)
}

// AllowErrors returns a parser that wraps `inner` and tries to continue parsing.
//
// After `n` errors, it returns any error `inner` does.
func AllowErrors[T any](inner SeriesParser[T], n int) FilteredSeriesParser[T] {
	if n == NoErrorLimit {
		return FilterErrors(inner, func(error) error { return nil })
	}

	count := 0

	return FilterErrors(inner, func(err error) error {
		count++

		if count > n {
			return ErrTooManyErrors
		}

		return nil
	})
}

type errorFilter[T any] struct {
	inner  SeriesParser[T]
	filter func(error) error
}

func newErrorFilter[T any](inner SeriesParser[T], filter func(error) error) FilteredSeriesParser[T] {
	return &errorFilter[T]{inner, filter}
}

func (f *errorFilter[T]) OnErr(callback func(error)) {
	filter := f.filter

	f.filter = func(err error) error {
		callback(ErrWithPosition(f.inner, err))

		return filter(err)
	}
}

func (f *errorFilter[T]) Position() string {
	return f.inner.Position()
}

func (f *errorFilter[T]) Next(ctx context.Context) (T, error) {
	var zero T

	for {
		res, err := f.inner.Next(ctx)
		if err != nil {
			if IsNonResumableErr(err) {
				// bypass the filter, and just propagate the error
				return zero, err
			}

			err = f.filter(err)
			if err != nil {
				return zero, err
			}

			continue
		}

		return res, nil
	}
}
