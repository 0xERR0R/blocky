package log

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
)

var _ = Describe("Context logger", func() {
	var (
		ctx  context.Context
		hook *test.Hook
	)

	BeforeEach(func() {
		ctx = context.Background()

		original := logger
		DeferCleanup(func() { logger = original })

		logger = newGlobalLogger()
		logger.SetOutput(io.Discard)
		logger.SetLevel(logrus.DebugLevel)

		hook = test.NewLocal(logger)
	})

	It("logs without fields when the context has none", func() {
		FromCtx(ctx).Info("message")

		Expect(hook.AllEntries()).Should(HaveLen(1))
		Expect(hook.LastEntry().Message).Should(Equal("message"))
		Expect(hook.LastEntry().Data).Should(BeEmpty())
	})

	It("adds the fields of the context to what its logger logs", func() {
		ctx = CtxWithFields(ctx, logrus.Fields{"a": 1, "b": "x"})

		FromCtx(ctx).Info("message")

		Expect(hook.LastEntry().Data).Should(Equal(logrus.Fields{"a": 1, "b": "x"}))
	})

	It("adds them to loggers derived from the context's logger", func() {
		ctx = CtxWithFields(ctx, logrus.Fields{"a": 1})
		err := errors.New("failed")

		FromCtx(ctx).WithError(err).WithField("b", 2).Warn("message")

		Expect(hook.LastEntry().Data).Should(Equal(logrus.Fields{"a": 1, "b": 2, "error": err}))
	})

	It("keeps the value a field got last", func() {
		ctx = CtxWithFields(ctx, logrus.Fields{"a": 1, "b": 1, "c": 1})
		ctx = CtxWithFields(ctx, logrus.Fields{"b": 2, "c": 2})

		FromCtx(ctx).WithField("c", 3).Info("message")

		Expect(hook.LastEntry().Data).Should(Equal(logrus.Fields{"a": 1, "b": 2, "c": 3}))
	})

	It("leaves the context the fields are added to unchanged", func() {
		outer := CtxWithFields(ctx, logrus.Fields{"a": 1})
		_ = CtxWithFields(outer, logrus.Fields{"a": 2, "b": 2})

		FromCtx(outer).Info("message")

		Expect(hook.LastEntry().Data).Should(Equal(logrus.Fields{"a": 1}))
	})

	It("keeps the fields in contexts derived from it", func() {
		ctx = CtxWithFields(ctx, logrus.Fields{"a": 1})

		derived, cancel := context.WithCancel(ctx)
		cancel()

		FromCtx(derived).Info("message")

		Expect(hook.LastEntry().Data).Should(Equal(logrus.Fields{"a": 1}))
		Expect(hook.LastEntry().Context).Should(BeIdenticalTo(derived))
	})

	It("shares one set of fields between contexts", func() {
		shared := logrus.Fields{"prefix": "resolver"}
		first := CtxWithFields(CtxWithFields(ctx, logrus.Fields{"request": 1}), shared)
		second := CtxWithFields(CtxWithFields(ctx, logrus.Fields{"request": 2}), shared)

		FromCtx(first).Info("first")
		FromCtx(second).Info("second")

		Expect(hook.AllEntries()[0].Data).Should(Equal(logrus.Fields{"prefix": "resolver", "request": 1}))
		Expect(hook.AllEntries()[1].Data).Should(Equal(logrus.Fields{"prefix": "resolver", "request": 2}))
		Expect(shared).Should(Equal(logrus.Fields{"prefix": "resolver"}))
	})

	It("gives a context the prefix PrefixedLog gives the global logger, in place of the one it had", func() {
		ctx = CtxWithFields(ctx, PrefixFields("first"))
		ctx = CtxWithFields(ctx, PrefixFields("second"))

		FromCtx(ctx).Info("message")

		Expect(hook.LastEntry().Data).Should(Equal(PrefixedLog("second").Data))
	})

	It("logs an entry without a context as it is", func() {
		logger.WithField("a", 1).Info("message")

		Expect(hook.LastEntry().Data).Should(Equal(logrus.Fields{"a": 1}))
	})

	Describe("lazy fields", func() {
		var built atomic.Int32

		BeforeEach(func() {
			built.Store(0)

			ctx = CtxWithLazyFields(ctx, func() logrus.Fields {
				built.Add(1)

				return logrus.Fields{"lazy": true}
			})
		})

		It("are not built when nothing is logged", func() {
			FromCtx(ctx).Trace("below the level of the logger")

			Expect(hook.AllEntries()).Should(BeEmpty())
			Expect(built.Load()).Should(BeZero())
		})

		It("are built once, when the first entry is logged", func() {
			FromCtx(ctx).Info("first")
			FromCtx(CtxWithFields(ctx, logrus.Fields{"a": 1})).Info("second")

			Expect(built.Load()).Should(BeEquivalentTo(1))
			Expect(hook.AllEntries()[0].Data).Should(Equal(logrus.Fields{"lazy": true}))
			Expect(hook.AllEntries()[1].Data).Should(Equal(logrus.Fields{"lazy": true, "a": 1}))
		})

		It("are built once by entries logged concurrently", func() {
			var wg sync.WaitGroup

			for range 50 {
				wg.Go(func() {
					FromCtx(ctx).Info("concurrent")
				})
			}

			wg.Wait()

			Expect(built.Load()).Should(BeEquivalentTo(1))
			Expect(hook.AllEntries()).Should(HaveLen(50))
		})
	})

	Describe("logger set by NewCtx", func() {
		var (
			own     *logrus.Logger
			ownHook *test.Hook
		)

		BeforeEach(func() {
			own, ownHook = test.NewNullLogger()
		})

		It("logs what the context logs, with the fields added to the context afterwards", func() {
			ctx, _ = NewCtx(ctx, own.WithField("own", true))
			ctx = CtxWithFields(ctx, logrus.Fields{"a": 1})
			ctx = CtxWithLazyFields(ctx, func() logrus.Fields { return logrus.Fields{"b": 2} })

			FromCtx(ctx).Info("message")

			Expect(hook.AllEntries()).Should(BeEmpty())
			Expect(ownHook.LastEntry().Data).Should(Equal(logrus.Fields{"own": true, "a": 1, "b": 2}))
		})

		It("decides at which levels the context logs", func() {
			Expect(IsLevelEnabled(ctx, logrus.DebugLevel)).Should(BeTrue())
			Expect(IsLevelEnabled(ctx, logrus.TraceLevel)).Should(BeFalse())

			own.SetLevel(logrus.TraceLevel)
			ctx, _ = NewCtx(ctx, logrus.NewEntry(own))
			ctx = CtxWithFields(ctx, logrus.Fields{"a": 1})

			Expect(IsLevelEnabled(ctx, logrus.TraceLevel)).Should(BeTrue())
		})

		It("replaces the fields the context had", func() {
			ctx = CtxWithFields(ctx, logrus.Fields{"a": 1})
			ctx, _ = NewCtx(ctx, logrus.NewEntry(logger))

			FromCtx(ctx).Info("message")

			Expect(hook.LastEntry().Data).Should(BeEmpty())
		})

		It("keeps the fields of the context the logger comes from", func() {
			from := FromCtx(CtxWithFields(ctx, logrus.Fields{"a": 1, "b": 1})).WithField("b", 2)

			ctx, _ = NewCtx(ctx, from)
			ctx = CtxWithFields(ctx, logrus.Fields{"c": 3})

			FromCtx(ctx).Info("message")

			Expect(hook.LastEntry().Data).Should(Equal(logrus.Fields{"a": 1, "b": 2, "c": 3}))
		})
	})
})
