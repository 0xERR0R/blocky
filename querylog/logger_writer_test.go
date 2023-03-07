package querylog

import (
	"time"

	"github.com/sirupsen/logrus/hooks/test"

	. "github.com/onsi/gomega"

	. "github.com/onsi/ginkgo/v2"
)

var _ = Describe("LoggerWriter", func() {
	Describe("logger query log", func() {
		When("New log entry was created", func() {
			It("should be logged", func() {
				writer := NewLoggerWriter()
				logger, hook := test.NewNullLogger()
				writer.logger = logger.WithField("k", "v")

				writer.Write(&LogEntry{
					Start:      time.Now(),
					DurationMs: 20,
				})

				Expect(hook.Entries).Should(HaveLen(1))
				Expect(hook.LastEntry().Message).Should(Equal("query resolved"))
			})
		})
		When("Cleanup is called", func() {
			It("should do nothing", func() {
				writer := NewLoggerWriter()
				writer.CleanUp()
			})
		})
	})
})
