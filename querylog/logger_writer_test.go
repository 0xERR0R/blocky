package querylog

import (
	"time"

	"github.com/sirupsen/logrus/hooks/test"

	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	. "github.com/onsi/ginkgo"
)

var _ = Describe("LoggerWriter", func() {

	Describe("logger query log", func() {
		When("New log entry was created", func() {
			It("should be logged", func() {
				writer := NewLoggerWriter()
				logger, hook := test.NewNullLogger()
				writer.logger = logger.WithField("k", "v")
				request := &model.Request{
					Req: util.NewMsgWithQuestion("google.de.", dns.TypeA),
					Log: logrus.NewEntry(logrus.New()),
				}
				res, err := util.NewMsgWithAnswer("example.com", 123, dns.TypeA, "123.124.122.122")

				Expect(err).Should(Succeed())
				response := &model.Response{
					Res:    res,
					Reason: "Resolved",
					RType:  model.ResponseTypeRESOLVED,
				}
				writer.Write(&Entry{
					Request:    request,
					Response:   response,
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
