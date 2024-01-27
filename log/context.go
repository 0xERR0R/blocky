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

func entryWithCtx(ctx context.Context, logger *logrus.Entry) *logrus.Entry {
	loggerCopy := *logger
	loggerCopy.Context = ctx

	return &loggerCopy
}

func WrapCtx(ctx context.Context, wrap func(*logrus.Entry) *logrus.Entry) (context.Context, *logrus.Entry) {
	logger := FromCtx(ctx)
	logger = wrap(logger)

	return NewCtx(ctx, logger)
}

func CtxWithFields(ctx context.Context, fields logrus.Fields) (context.Context, *logrus.Entry) {
	return WrapCtx(ctx, func(e *logrus.Entry) *logrus.Entry {
		return e.WithFields(fields)
	})
}
