package resolver

import (
	"blocky/config"
	"blocky/util"
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	log "github.com/sirupsen/logrus"
)

var _ = Describe("QueryLoggingResolver", func() {
	var (
		sut        *QueryLoggingResolver
		sutConfig  config.QueryLogConfig
		err        error
		resp       *Response
		m          *resolverMock
		tmpDir     string
		mockAnswer *dns.Msg
	)

	BeforeEach(func() {
		mockAnswer = new(dns.Msg)
		tmpDir, err = ioutil.TempDir("", "queryLoggingResolver")
		Expect(err).Should(Succeed())
	})

	JustBeforeEach(func() {
		sut = NewQueryLoggingResolver(sutConfig).(*QueryLoggingResolver)
		m = &resolverMock{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: mockAnswer, Reason: "reason"}, nil)
		sut.Next(m)
	})
	AfterEach(func() {
		Expect(err).Should(Succeed())
		_ = os.RemoveAll(tmpDir)
	})

	Describe("Process request", func() {

		When("Resolver has no configuration", func() {
			BeforeEach(func() {
				sutConfig = config.QueryLogConfig{}
			})
			It("should process request without query logging", func() {
				resp, err = sut.Resolve(newRequest("example.com.", dns.TypeA))

				m.AssertExpectations(GinkgoT())
				Expect(resp.RType).Should(Equal(RESOLVED))
			})
		})
		When("Configuration with logging per client", func() {
			BeforeEach(func() {
				sutConfig = config.QueryLogConfig{
					Dir:       tmpDir,
					PerClient: true,
				}
				mockAnswer, _ = util.NewMsgWithAnswer("example.com.", 300, dns.TypeA, "123.122.121.120")
			})
			It("should create a log file per client", func() {
				By("request from client 1", func() {
					resp, err = sut.Resolve(newRequestWithClient("example.com.", dns.TypeA, "192.168.178.25", "client1"))
					Expect(err).Should(Succeed())
				})
				By("request from client 2, has name with special chars, should be escaped", func() {
					resp, err = sut.Resolve(newRequestWithClient("example.com.", dns.TypeA, "192.168.178.26", "cl/ient2\\$%&test"))
					Expect(err).Should(Succeed())
				})

				time.Sleep(100 * time.Millisecond)
				m.AssertExpectations(GinkgoT())

				By("check log for client1", func() {
					csvLines := readCsv(filepath.Join(tmpDir, fmt.Sprintf("%s_client1.log", time.Now().Format("2006-01-02"))))

					Expect(csvLines).Should(HaveLen(1))
					Expect(csvLines[0][1]).Should(Equal("192.168.178.25"))
					Expect(csvLines[0][2]).Should(Equal("client1"))
					Expect(csvLines[0][4]).Should(Equal("reason"))
					Expect(csvLines[0][5]).Should(Equal("A (example.com.)"))
					Expect(csvLines[0][6]).Should(Equal("A (123.122.121.120)"))
				})

				By("check log for client2", func() {
					csvLines := readCsv(filepath.Join(tmpDir, fmt.Sprintf("%s_cl_ient2_test.log", time.Now().Format("2006-01-02"))))

					Expect(csvLines).Should(HaveLen(1))
					Expect(csvLines[0][1]).Should(Equal("192.168.178.26"))
					Expect(csvLines[0][2]).Should(Equal("cl/ient2\\$%&test"))
					Expect(csvLines[0][4]).Should(Equal("reason"))
					Expect(csvLines[0][5]).Should(Equal("A (example.com.)"))
					Expect(csvLines[0][6]).Should(Equal("A (123.122.121.120)"))
				})
			})
		})
		When("Configuration with logging in one file for all clients", func() {
			BeforeEach(func() {
				sutConfig = config.QueryLogConfig{
					Dir:       tmpDir,
					PerClient: false,
				}
				mockAnswer, _ = util.NewMsgWithAnswer("example.com.", 300, dns.TypeA, "123.122.121.120")
			})
			It("should create one log file for all clients", func() {
				By("request from client 1", func() {
					resp, err = sut.Resolve(newRequestWithClient("example.com.", dns.TypeA, "192.168.178.25", "client1"))
					Expect(err).Should(Succeed())
				})
				By("request from client 2, has name with special chars, should be escaped", func() {
					resp, err = sut.Resolve(newRequestWithClient("example.com.", dns.TypeA, "192.168.178.26", "client2"))
					Expect(err).Should(Succeed())
				})

				time.Sleep(100 * time.Millisecond)
				m.AssertExpectations(GinkgoT())

				By("check log", func() {
					csvLines := readCsv(filepath.Join(tmpDir, fmt.Sprintf("%s_ALL.log", time.Now().Format("2006-01-02"))))

					Expect(csvLines).Should(HaveLen(2))
					// client1 -> first line
					Expect(csvLines[0][1]).Should(Equal("192.168.178.25"))
					Expect(csvLines[0][2]).Should(Equal("client1"))
					Expect(csvLines[0][4]).Should(Equal("reason"))
					Expect(csvLines[0][5]).Should(Equal("A (example.com.)"))
					Expect(csvLines[0][6]).Should(Equal("A (123.122.121.120)"))

					// client2 -> second line
					Expect(csvLines[1][1]).Should(Equal("192.168.178.26"))
					Expect(csvLines[1][2]).Should(Equal("client2"))
					Expect(csvLines[1][4]).Should(Equal("reason"))
					Expect(csvLines[1][5]).Should(Equal("A (example.com.)"))
					Expect(csvLines[1][6]).Should(Equal("A (123.122.121.120)"))
				})
			})
		})
	})

	Describe("Configuration output", func() {
		When("resolver is enabled", func() {
			BeforeEach(func() {
				sutConfig = config.QueryLogConfig{
					Dir:              tmpDir,
					PerClient:        true,
					LogRetentionDays: 0,
				}
			})
			It("should return configuration", func() {
				c := sut.Configuration()
				Expect(len(c) > 1).Should(BeTrue())
			})
		})

		When("resolver is disabled", func() {
			BeforeEach(func() {
				sutConfig = config.QueryLogConfig{}
			})
			It("should return 'disabled'", func() {
				c := sut.Configuration()
				Expect(c).Should(HaveLen(1))
				Expect(c).Should(Equal([]string{"deactivated"}))
			})
		})
	})

	Describe("Clean up of query log directory", func() {
		When("Log directory does not exist", func() {

			It("should exit with error", func() {
				defer func() { log.StandardLogger().ExitFunc = nil }()

				var fatal bool

				log.StandardLogger().ExitFunc = func(int) { fatal = true }
				_ = NewQueryLoggingResolver(config.QueryLogConfig{Dir: "notExists"})

				Expect(fatal).Should(BeTrue())
			})
		})
		When("not existing log directory is configured, log retention is enabled", func() {
			It("should exit with error", func() {
				defer func() { log.StandardLogger().ExitFunc = nil }()

				var fatal bool

				log.StandardLogger().ExitFunc = func(int) { fatal = true }

				sut := NewQueryLoggingResolver(config.QueryLogConfig{
					Dir:              "wrongDir",
					LogRetentionDays: 7,
				}).(*QueryLoggingResolver)

				sut.doCleanUp()
				Expect(fatal).Should(BeTrue())
			})
		})
		When("log directory contains old files", func() {
			It("should remove files older than defined log retention", func() {

				// create 2 files, 7 and 8 days old
				dateBefore7Days := time.Now().AddDate(0, 0, -7)
				dateBefore8Days := time.Now().AddDate(0, 0, -8)

				f1, err := os.Create(filepath.Join(tmpDir, fmt.Sprintf("%s-test.log", dateBefore7Days.Format("2006-01-02"))))
				Expect(err).Should(Succeed())

				f2, err := os.Create(filepath.Join(tmpDir, fmt.Sprintf("%s-test.log", dateBefore8Days.Format("2006-01-02"))))
				Expect(err).Should(Succeed())

				sut := NewQueryLoggingResolver(config.QueryLogConfig{
					Dir:              tmpDir,
					LogRetentionDays: 7,
				})

				sut.(*QueryLoggingResolver).doCleanUp()

				// file 1 exist
				_, err = os.Stat(f1.Name())
				Expect(err).Should(Succeed())

				// file 2 was deleted
				_, err = os.Stat(f2.Name())
				Expect(err).Should(HaveOccurred())
				Expect(os.IsNotExist(err)).Should(BeTrue())
			})
		})
	})

})

func readCsv(file string) [][]string {
	var result [][]string

	csvFile, err := os.Open(file)
	Expect(err).Should(Succeed())

	reader := csv.NewReader(bufio.NewReader(csvFile))
	reader.Comma = '\t'

	for {
		line, err := reader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Fatal("can't read line", err)
		}

		result = append(result, line)
	}

	return result
}
