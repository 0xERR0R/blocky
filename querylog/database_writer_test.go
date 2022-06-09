package querylog

import (
	"time"

	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/sqlite"

	. "github.com/onsi/gomega"

	. "github.com/onsi/ginkgo/v2"
)

var _ = Describe("DatabaseWriter", func() {

	Describe("Database query log", func() {
		When("New log entry was created", func() {
			It("should be persisted in the database", func() {
				sqlite := sqlite.Open("file::memory:")
				writer, err := newDatabaseWriter(sqlite, 7, time.Millisecond)
				Expect(err).Should(Succeed())
				request := &model.Request{
					Req: util.NewMsgWithQuestion("google.de.", dns.Type(dns.TypeA)),
					Log: logrus.NewEntry(log.Log()),
				}
				res, err := util.NewMsgWithAnswer("example.com", 123, dns.Type(dns.TypeA), "123.124.122.122")

				Expect(err).Should(Succeed())
				response := &model.Response{
					Res:    res,
					Reason: "Resolved",
					RType:  model.ResponseTypeRESOLVED,
				}
				writer.Write(&LogEntry{
					Request:    request,
					Response:   response,
					Start:      time.Now(),
					DurationMs: 20,
				})
				Eventually(func() (res int64) {
					result := writer.db.Find(&logEntry{})

					result.Count(&res)

					return res
				}, "1s").Should(BeNumerically("==", 1))
			})
		})

		When("There are log entries with timestamp exceeding the retention period", func() {
			It("these old entries should be deleted", func() {
				sqlite := sqlite.Open("file::memory:")
				writer, err := newDatabaseWriter(sqlite, 1, time.Millisecond)
				Expect(err).Should(Succeed())

				request := &model.Request{
					Req: util.NewMsgWithQuestion("google.de.", dns.Type(dns.TypeA)),
					Log: logrus.NewEntry(log.Log()),
				}
				res, err := util.NewMsgWithAnswer("example.com", 123, dns.Type(dns.TypeA), "123.124.122.122")

				Expect(err).Should(Succeed())
				response := &model.Response{
					Res:    res,
					Reason: "Resolved",
					RType:  model.ResponseTypeRESOLVED,
				}

				// one entry with now as timestamp
				writer.Write(&LogEntry{
					Request:    request,
					Response:   response,
					Start:      time.Now(),
					DurationMs: 20,
				})

				// one entry before 2 days -> should be deleted
				writer.Write(&LogEntry{
					Request:    request,
					Response:   response,
					Start:      time.Now().AddDate(0, 0, -2),
					DurationMs: 20,
				})

				// 2 entries in the database
				Eventually(func() int64 {
					var res int64
					result := writer.db.Find(&logEntry{})

					result.Count(&res)

					return res
				}, "1s").Should(BeNumerically("==", 2))

				// do cleanup now
				writer.CleanUp()

				// now only 1 entry in the database
				Eventually(func() (res int64) {
					result := writer.db.Find(&logEntry{})

					result.Count(&res)

					return res
				}, "1s").Should(BeNumerically("==", 1))
			})
		})

		When("mysql connection parameters wrong", func() {
			It("should be log with fatal", func() {
				_, err := NewDatabaseWriter("mysql", "wrong param", 7, 1)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(HavePrefix("can't create database connection"))
			})
		})

		When("postgresql connection parameters wrong", func() {
			It("should be log with fatal", func() {
				_, err := NewDatabaseWriter("postgresql", "wrong param", 7, 1)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(HavePrefix("can't create database connection"))
			})
		})

		When("invalid database type is specified", func() {
			It("should be log with fatal", func() {
				_, err := NewDatabaseWriter("invalidsql", "", 7, 1)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(HavePrefix("incorrect database type provided"))
			})
		})
	})

})
