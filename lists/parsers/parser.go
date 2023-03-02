package parsers

import (
	"context"
	"errors"
	"fmt"
	"io"
)

// SeriesParser parses a series of `T`.
type SeriesParser[T any] interface {
	// Next advances the cursor in the underlying data source,
	// and returns a `T`, or an error.
	//
	// Fatal parse errors, where no more calls to `Next` should
	// be made are of type `NonResumableError`.
	// Other errors apply to the item being parsed, and have no
	// impact on the rest of the series.
	Next(context.Context) (T, error)

	// Position returns a string that gives an user readable indication
	// as to where in the parser's underlying data source the cursor is.
	//
	// The string should be understandable easily by the user.
	Position() string
}

// ForEach is a helper for consuming a parser.
//
// It stops iteration at the first error encountered.
// If that error is `io.EOF`, `nil` is returned instead.
// Any other error is wrapped with the parser's position using `ErrWithPosition`.
//
// To continue iteration on resumable errors, use with `FilterErrors`.
func ForEach[T any](ctx context.Context, parser SeriesParser[T], callback func(T) error) (rerr error) {
	defer func() {
		rerr = ErrWithPosition(parser, rerr)
	}()

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		res, err := parser.Next(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}

			return err
		}

		err = callback(res)
		if err != nil {
			return err
		}
	}
}

// ErrWithPosition adds the `parser`'s position to the given `err`.
func ErrWithPosition[T any](parser SeriesParser[T], err error) error {
	if err == nil {
		return nil
	}

	return fmt.Errorf("%s: %w", parser.Position(), err)
}

// IsNonResumableErr is a helper to check if an error returned by a parser is resumable.
func IsNonResumableErr(err error) bool {
	var nonResumableError *NonResumableError

	return errors.As(err, &nonResumableError)
}

// NonResumableError represents an error from which a parser cannot recover.
type NonResumableError struct {
	inner error
}

// NewNonResumableError creates and returns a new `NonResumableError`.
func NewNonResumableError(inner error) error {
	return &NonResumableError{inner}
}

func (e *NonResumableError) Error() string {
	return fmt.Sprintf("non resumable parse error: %s", e.inner.Error())
}

func (e *NonResumableError) Unwrap() error {
	return e.inner
}
