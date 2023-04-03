package parsers

import "context"

// Adapt returns a parser that wraps `inner` converting each parsed value.
func Adapt[From, To any](inner SeriesParser[From], adapt func(From) To) SeriesParser[To] {
	return TryAdapt(inner, func(from From) (To, error) {
		return adapt(from), nil
	})
}

// TryAdapt returns a parser that wraps `inner` and tries to convert each parsed value.
func TryAdapt[From, To any](inner SeriesParser[From], adapt func(From) (To, error)) SeriesParser[To] {
	return newAdapter(inner, adapt)
}

// TryAdaptMethod returns a parser that wraps `inner` and tries to convert each parsed value
// using the given method with pointer receiver of `To`.
func TryAdaptMethod[ToPtr *To, From, To any](
	inner SeriesParser[From], method func(ToPtr, From) error,
) SeriesParser[*To] {
	return TryAdapt(inner, func(from From) (*To, error) {
		res := new(To)

		err := method(res, from)
		if err != nil {
			return nil, err
		}

		return res, nil
	})
}

type adapter[From, To any] struct {
	inner SeriesParser[From]
	adapt func(From) (To, error)
}

func newAdapter[From, To any](inner SeriesParser[From], adapt func(From) (To, error)) SeriesParser[To] {
	return &adapter[From, To]{inner, adapt}
}

func (a *adapter[From, To]) Position() string {
	return a.inner.Position()
}

func (a *adapter[From, To]) Next(ctx context.Context) (To, error) {
	from, err := a.inner.Next(ctx)
	if err != nil {
		var zero To

		return zero, err
	}

	res, err := a.adapt(from)
	if err != nil {
		var zero To

		return zero, err
	}

	return res, nil
}
