package querylog

import (
	"time"

	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/sqlite"

	. "github.com/onsi/gomega"

	. "github.com/onsi/ginkgo"
)

var _ = Describe("DatabaseWriter", func() {

	Describe("Database query log", func() {
		When("New log entry was created", func() {
			It("should be persisted in the database", func() {
				sqlite := sqlite.Open("file::memory:")
				writer, err := newDatabaseWriter(sqlite, 7, 1)
				Expect(err).Should(Succeed())
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
				time.Sleep(500 * time.Millisecond)

				result := writer.db.Find(&logEntry{})

				var cnt int64
				result.Count(&cnt)

				Expect(cnt).Should(Equal(int64(1)))

			})
		})

		When("There are log entries with timestamp exceeding the retention period", func() {
			It("these old entries should be deleted", func() {
				sqlite := sqlite.Open("file::memory:")
				writer, err := newDatabaseWriter(sqlite, 1, 1)
				Expect(err).Should(Succeed())

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

				// one entry with now as timestamp
				writer.Write(&Entry{
					Request:    request,
					Response:   response,
					Start:      time.Now(),
					DurationMs: 20,
				})

				// one entry before 2 days -> should be deleted
				writer.Write(&Entry{
					Request:    request,
					Response:   response,
					Start:      time.Now().AddDate(0, 0, -2),
					DurationMs: 20,
				})

				result := writer.db.Find(&logEntry{})

				time.Sleep(500 * time.Millisecond)

				var cnt int64
				result.Count(&cnt)

				// 2 entries in the database
				Expect(cnt).Should(Equal(int64(2)))

				// do cleanup now
				writer.CleanUp()

				result.Count(&cnt)

				// now only 1 entry in the database
				Expect(cnt).Should(Equal(int64(1)))
			})
		})

		When("connection parameters wrong", func() {
			It("should be log with fatal", func() {
				_, err := NewDatabaseWriter("wrong param", 7, 1)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(HavePrefix("can't create database connection"))
			})
		})
	})

})
