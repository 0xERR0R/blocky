package log

import (
	"context"
	"sync"

	"github.com/sirupsen/logrus"
)

type ctxKey struct{}

// ctxFields is what a context adds to its logger: fields, or the logger set by NewCtx.
//
// The fields are not copied into each logger derived from the context: most requests log
// nothing at the default level. ctxFieldsHook adds them to an entry when it is logged.
type ctxFields struct {
	// outer has the fields added before
	outer *ctxFields

	fields logrus.Fields

	// lazy builds fields when the first entry is logged
	lazy func() logrus.Fields
	once sync.Once

	// logger was set by NewCtx. Fields added after it are copied into it right away:
	// only the global logger is known to have ctxFieldsHook.
	logger *logrus.Entry
}

func ctxFieldsOf(ctx context.Context) *ctxFields {
	fields, _ := ctx.Value(ctxKey{}).(*ctxFields)

	return fields
}

func (f *ctxFields) get() logrus.Fields {
	if f.lazy != nil {
		f.once.Do(func() { f.fields = f.lazy() })
	}

	return f.fields
}

// NewCtx returns a context whose logger is logger, and that logger.
func NewCtx(ctx context.Context, logger *logrus.Entry) (context.Context, *logrus.Entry) {
	fields := &ctxFields{logger: logger}

	// the logger keeps the fields of the context it comes from
	if logger.Context != nil {
		fields.outer = ctxFieldsOf(logger.Context)
	}

	ctx = context.WithValue(ctx, ctxKey{}, fields)

	return ctx, entryWithCtx(ctx, logger)
}

// FromCtx returns the logger of ctx. What it logs has the fields of ctx.
func FromCtx(ctx context.Context) *logrus.Entry {
	if fields := ctxFieldsOf(ctx); fields != nil && fields.logger != nil {
		// Ensure `logger.Context == ctx`, not always the case since `ctx` could be a child of `logger.Context`
		return entryWithCtx(ctx, fields.logger)
	}

	return &logrus.Entry{Logger: Log(), Context: ctx}
}

// IsLevelEnabled reports whether the logger of ctx logs at level. Use it to skip the
// work for an entry that would not be logged.
func IsLevelEnabled(ctx context.Context, level logrus.Level) bool {
	if fields := ctxFieldsOf(ctx); fields != nil && fields.logger != nil {
		return fields.logger.Logger.IsLevelEnabled(level)
	}

	return Log().IsLevelEnabled(level)
}

func entryWithCtx(ctx context.Context, logger *logrus.Entry) *logrus.Entry {
	loggerCopy := *logger
	loggerCopy.Context = ctx

	return &loggerCopy
}

// CtxWithFields returns a context that adds fields to what its logger logs, replacing
// the fields ctx already has under the same names.
//
// fields must not be modified afterwards. The same fields can be added to any number of
// contexts.
func CtxWithFields(ctx context.Context, fields logrus.Fields) context.Context {
	return withFields(ctx, &ctxFields{fields: fields})
}

// CtxWithLazyFields is CtxWithFields for fields that take work to build: build is called
// when the first entry is logged, and never if none is.
func CtxWithLazyFields(ctx context.Context, build func() logrus.Fields) context.Context {
	return withFields(ctx, &ctxFields{lazy: build})
}

func withFields(ctx context.Context, fields *ctxFields) context.Context {
	fields.outer = ctxFieldsOf(ctx)

	if fields.outer != nil && fields.outer.logger != nil {
		ctx, _ = NewCtx(ctx, fields.outer.logger.WithFields(fields.get()))

		return ctx
	}

	return context.WithValue(ctx, ctxKey{}, fields)
}

// ctxFieldsHook adds the fields of an entry's context to the entry.
type ctxFieldsHook struct{}

// Levels implements `logrus.Hook`.
func (ctxFieldsHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// Fire implements `logrus.Hook`.
func (ctxFieldsHook) Fire(entry *logrus.Entry) error {
	if entry.Context == nil {
		return nil
	}

	// From the fields added last: a field keeps the value it got last, and the fields of
	// the entry itself were all set after those of its context.
	for fields := ctxFieldsOf(entry.Context); fields != nil; fields = fields.outer {
		for name, value := range fields.get() {
			if _, ok := entry.Data[name]; ok {
				continue
			}

			if entry.Data == nil {
				entry.Data = make(logrus.Fields)
			}

			entry.Data[name] = value
		}
	}

	return nil
}
