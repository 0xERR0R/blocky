package log

import (
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
)

var _ = Describe("Buffer", func() {
	var (
		buffer *Buffer
		target *logrus.Logger
		hook   *test.Hook
	)

	BeforeEach(func() {
		buffer = NewBuffer()

		target, hook = test.NewNullLogger()
		target.SetLevel(logrus.TraceLevel)
	})

	It("replays each entry with its level, message, fields and time, in order", func() {
		at := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

		buffer.Entry().WithField("prefix", "config").WithTime(at).Warn("first")
		buffer.Entry().Trace("second")

		buffer.Replay(target)

		entries := hook.AllEntries()
		Expect(entries).Should(HaveLen(2))

		Expect(entries[0].Level).Should(Equal(logrus.WarnLevel))
		Expect(entries[0].Message).Should(Equal("first"))
		Expect(entries[0].Data).Should(Equal(logrus.Fields{"prefix": "config"}))
		Expect(entries[0].Time).Should(Equal(at))

		Expect(entries[1].Level).Should(Equal(logrus.TraceLevel))
		Expect(entries[1].Message).Should(Equal("second"))
	})

	It("replays only what the target's level allows", func() {
		target.SetLevel(logrus.WarnLevel)

		buffer.Entry().Debug("dropped")
		buffer.Entry().Error("kept")

		buffer.Replay(target)

		Expect(hook.AllEntries()).Should(HaveLen(1))
		Expect(hook.LastEntry().Message).Should(Equal("kept"))
	})

	It("replays each entry once", func() {
		buffer.Entry().Info("once")

		buffer.Replay(target)
		buffer.Replay(target)

		Expect(hook.AllEntries()).Should(HaveLen(1))
	})

	It("holds entries logged concurrently", func() {
		const count = 50

		var wg sync.WaitGroup

		for range count {
			wg.Go(func() {
				buffer.Entry().Info("concurrent")
			})
		}

		wg.Wait()

		buffer.Replay(target)

		Expect(hook.AllEntries()).Should(HaveLen(count))
	})
})
