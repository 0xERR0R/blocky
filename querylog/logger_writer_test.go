package querylog

import (
	"log/slog"
	"time"

	"github.com/0xERR0R/blocky/log"

	. "github.com/onsi/gomega"

	. "github.com/onsi/ginkgo/v2"
)

// attrValue returns the value of the first attr with the given key.
func attrValue(attrs []slog.Attr, key string) (slog.Value, bool) {
	for _, a := range attrs {
		if a.Key == key {
			return a.Value, true
		}
	}

	return slog.Value{}, false
}

var _ = Describe("LoggerWriter", func() {
	Describe("logger query log", func() {
		When("New log entry was created", func() {
			It("should be logged", func() {
				writer := NewLoggerWriter()
				logger, rec := log.NewRecorder()
				writer.logger = logger

				writer.Write(&LogEntry{
					Start:      time.Now(),
					ClientIP:   "192.168.1.5",
					DurationMs: 20,
				})

				Expect(rec.Records()).Should(HaveLen(1))
				Expect(rec.LastMessage()).Should(Equal("query resolved"))

				// Fields must be flat and snake_case, not nested under "entry".
				_, hasEntry := rec.Attr("entry")
				Expect(hasEntry).Should(BeFalse())

				clientIP, ok := rec.Attr("client_ip")
				Expect(ok).Should(BeTrue())
				Expect(clientIP.String()).Should(Equal("192.168.1.5"))

				durationMs, ok := rec.Attr("duration_ms")
				Expect(ok).Should(BeTrue())
				Expect(durationMs.Int64()).Should(Equal(int64(20)))
			})
		})
		When("Cleanup is called", func() {
			It("should do nothing", func() {
				writer := NewLoggerWriter()
				writer.CleanUp()
			})
		})
	})

	Describe("LogEntryFields", func() {
		It("should return log fields", func() {
			entry := LogEntry{
				ClientIP:     "ip",
				DurationMs:   100,
				QuestionType: "qtype",
				ResponseCode: "rcode",
			}

			fields := LogEntryFields(&entry)

			clientIP, ok := attrValue(fields, "client_ip")
			Expect(ok).Should(BeTrue())
			Expect(clientIP.String()).Should(Equal(entry.ClientIP))

			durationMs, ok := attrValue(fields, "duration_ms")
			Expect(ok).Should(BeTrue())
			Expect(durationMs.Int64()).Should(Equal(entry.DurationMs))

			questionType, ok := attrValue(fields, "question_type")
			Expect(ok).Should(BeTrue())
			Expect(questionType.String()).Should(Equal(entry.QuestionType))

			_, ok = attrValue(fields, "response_code")
			Expect(ok).Should(BeTrue())

			// zero-valued fields are omitted
			_, ok = attrValue(fields, "client_names")
			Expect(ok).Should(BeFalse())
			_, ok = attrValue(fields, "question_name")
			Expect(ok).Should(BeFalse())
		})
	})

	DescribeTable("withoutZeroes",
		func(attr slog.Attr, isZero bool) {
			fields := withoutZeroes(attr)

			if isZero {
				Expect(fields).Should(BeEmpty())
			} else {
				Expect(fields).ShouldNot(BeEmpty())
			}
		},
		Entry("empty string",
			slog.String("a", ""),
			true),
		Entry("non-empty string",
			slog.String("a", "something"),
			false),
		Entry("zero int",
			slog.Int("a", 0),
			true),
		Entry("non-zero int",
			slog.Int("a", 1),
			false),
	)
})
