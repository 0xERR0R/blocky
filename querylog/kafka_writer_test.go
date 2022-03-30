package querylog

import (
	"time"

	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"

	. "github.com/onsi/gomega"

	. "github.com/onsi/ginkgo/v2"
)

var _ = Describe("KafkaWriter", func() {

	Describe("Kafka query log", func() {
		When("New log entry was created", func() {
			It("should be produced in the kafka stream", func() {
				kafkaConfig := `{"topic":"dns","test.mock.num.brokers":"3"}`
				writer, err := NewKafkaWriter(kafkaConfig)
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
				writer.Write(&LogEntry{
					Request:    request,
					Response:   response,
					Start:      time.Now(),
					DurationMs: 20,
				})
				Eventually(func() (res int) {
					return writer.kafka.Len()
				}, "50ms").Should(BeNumerically("==", 1))
			})
		})

		When("kafka bad json target", func() {
			It("should return an error", func() {
				_, err := NewKafkaWriter("bad parameters")
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(HavePrefix("can't parse json object"))
			})
		})

		When("kafka parameters wrong", func() {
			It("should return an error", func() {
				_, err := NewKafkaWriter(`{ "non-existing-field": "test" }`)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(HavePrefix("can't create kafka producer: No such configuration"))
			})
		})
	})
})
