package log

import (
	"context"

	"github.com/sirupsen/logrus"
)

type ctxKey struct{}

func NewCtx(ctx context.Context, logger *logrus.Entry) (context.Context, *logrus.Entry) {
	ctx = context.WithValue(ctx, ctxKey{}, logger)

	return ctx, entryWithCtx(ctx, logger)
}

func FromCtx(ctx context.Context) *logrus.Entry {
	logger, ok := ctx.Value(ctxKey{}).(*logrus.Entry)
	if !ok {
		// Fallback to the global logger
		return logrus.NewEntry(Log())
	}

	// Ensure `logger.Context == ctx`, not always the case since `ctx` could be a child of `logger.Context`
	return entryWithCtx(ctx, logger)
}

// baseFromCtx returns the entry stored in the context (or a fresh entry on the
// global logger) WITHOUT copying it. The returned entry's `Context` may point at
// an ancestor of `ctx`; callers that need `Context == ctx` must wrap it (FromCtx
// copies via entryWithCtx; WrapCtx re-stamps Context via NewCtx).
func baseFromCtx(ctx context.Context) *logrus.Entry {
	if logger, ok := ctx.Value(ctxKey{}).(*logrus.Entry); ok {
		return logger
	}

	// Fallback to the global logger
	return logrus.NewEntry(Log())
}

func entryWithCtx(ctx context.Context, logger *logrus.Entry) *logrus.Entry {
	loggerCopy := *logger
	loggerCopy.Context = ctx

	return &loggerCopy
}

// WrapCtx derives a new context logger by applying `wrap` to the context-stored entry.
//
// `wrap` MUST return a new entry (e.g. via WithField/WithFields) and MUST NOT mutate
// the entry it is given in place: the base entry is passed without copying (the wrapped
// result is a fresh entry and NewCtx re-stamps its Context), so an in-place mutation
// would corrupt the shared context-stored logger.
func WrapCtx(ctx context.Context, wrap func(*logrus.Entry) *logrus.Entry) (context.Context, *logrus.Entry) {
	logger := wrap(baseFromCtx(ctx))

	return NewCtx(ctx, logger)
}

func CtxWithFields(ctx context.Context, fields logrus.Fields) (context.Context, *logrus.Entry) {
	return WrapCtx(ctx, func(e *logrus.Entry) *logrus.Entry {
		return e.WithFields(fields)
	})
}
