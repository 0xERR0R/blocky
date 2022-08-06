package resolver

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/querylog"

	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

type SlowMockWriter struct {
	entries []*querylog.LogEntry
}

func (m *SlowMockWriter) Write(entry *querylog.LogEntry) {
	m.entries = append(m.entries, entry)

	time.Sleep(time.Second)
}

func (m *SlowMockWriter) CleanUp() {
}

var _ = Describe("QueryLoggingResolver", func() {
	var (
		sut        *QueryLoggingResolver
		sutConfig  config.QueryLogConfig
		err        error
		resp       *Response
		m          *MockResolver
		tmpDir     *helpertest.TmpFolder
		mockAnswer *dns.Msg
	)

	BeforeEach(func() {
		mockAnswer = new(dns.Msg)
		tmpDir = helpertest.NewTmpFolder("queryLoggingResolver")
		Expect(tmpDir.Error).Should(Succeed())
		DeferCleanup(tmpDir.Clean)
	})

	JustBeforeEach(func() {
		sut = NewQueryLoggingResolver(sutConfig).(*QueryLoggingResolver)
		DeferCleanup(func() { close(sut.logChan) })
		m = &MockResolver{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: mockAnswer, Reason: "reason"}, nil)
		sut.Next(m)
	})

	Describe("Process request", func() {
		When("Resolver has no configuration", func() {
			BeforeEach(func() {
				sutConfig = config.QueryLogConfig{
					CreationAttempts: 1,
					CreationCooldown: config.Duration(time.Millisecond),
				}
			})
			It("should process request without query logging", func() {
				resp, err = sut.Resolve(newRequest("example.com.", dns.Type(dns.TypeA)))

				m.AssertExpectations(GinkgoT())
				Expect(resp.RType).Should(Equal(ResponseTypeRESOLVED))
			})
		})
		When("Configuration with logging per client", func() {
			BeforeEach(func() {
				sutConfig = config.QueryLogConfig{
					Target:           tmpDir.Path,
					Type:             config.QueryLogTypeCsvClient,
					CreationAttempts: 1,
					CreationCooldown: config.Duration(time.Millisecond),
				}
				mockAnswer, _ = util.NewMsgWithAnswer("example.com.", 300, dns.Type(dns.TypeA), "123.122.121.120")
			})
			It("should create a log file per client", func() {
				By("request from client 1", func() {
					resp, err = sut.Resolve(newRequestWithClient("example.com.", dns.Type(dns.TypeA), "192.168.178.25", "client1"))
					Expect(err).Should(Succeed())
				})
				By("request from client 2, has name with special chars, should be escaped", func() {
					resp, err = sut.Resolve(newRequestWithClient(
						"example.com.", dns.Type(dns.TypeA), "192.168.178.26", "cl/ient2\\$%&test",
					))
					Expect(err).Should(Succeed())
				})

				m.AssertExpectations(GinkgoT())

				By("check log for client1", func() {
					Eventually(func(g Gomega) {
						csvLines, err := readCsv(tmpDir.JoinPath(
							fmt.Sprintf("%s_client1.log", time.Now().Format("2006-01-02"))))

						g.Expect(err).Should(Succeed())
						g.Expect(csvLines).Should(Not(BeEmpty()))
						g.Expect(csvLines[0][1]).Should(Equal("192.168.178.25"))
						g.Expect(csvLines[0][2]).Should(Equal("client1"))
						g.Expect(csvLines[0][4]).Should(Equal("reason"))
						g.Expect(csvLines[0][5]).Should(Equal("A (example.com.)"))
						g.Expect(csvLines[0][6]).Should(Equal("A (123.122.121.120)"))
					}, "1s").Should(Succeed())

				})

				By("check log for client2", func() {
					Eventually(func(g Gomega) {
						csvLines, err := readCsv(tmpDir.JoinPath(
							fmt.Sprintf("%s_cl_ient2_test.log", time.Now().Format("2006-01-02"))))

						g.Expect(err).Should(Succeed())
						g.Expect(csvLines).Should(HaveLen(1))
						g.Expect(csvLines[0][1]).Should(Equal("192.168.178.26"))
						g.Expect(csvLines[0][2]).Should(Equal("cl/ient2\\$%&test"))
						g.Expect(csvLines[0][4]).Should(Equal("reason"))
						g.Expect(csvLines[0][5]).Should(Equal("A (example.com.)"))
						g.Expect(csvLines[0][6]).Should(Equal("A (123.122.121.120)"))
					}, "1s").Should(Succeed())
				})
			})
		})
		When("Configuration with logging in one file for all clients", func() {
			BeforeEach(func() {
				sutConfig = config.QueryLogConfig{
					Target:           tmpDir.Path,
					Type:             config.QueryLogTypeCsv,
					CreationAttempts: 1,
					CreationCooldown: config.Duration(time.Millisecond),
				}
				mockAnswer, _ = util.NewMsgWithAnswer("example.com.", 300, dns.Type(dns.TypeA), "123.122.121.120")
			})
			It("should create one log file for all clients", func() {
				By("request from client 1", func() {
					resp, err = sut.Resolve(newRequestWithClient("example.com.", dns.Type(dns.TypeA), "192.168.178.25", "client1"))
					Expect(err).Should(Succeed())
				})
				By("request from client 2, has name with special chars, should be escaped", func() {
					resp, err = sut.Resolve(newRequestWithClient("example.com.", dns.Type(dns.TypeA), "192.168.178.26", "client2"))
					Expect(err).Should(Succeed())
				})

				m.AssertExpectations(GinkgoT())

				By("check log", func() {
					Eventually(func(g Gomega) {
						csvLines, err := readCsv(tmpDir.JoinPath(
							fmt.Sprintf("%s_ALL.log", time.Now().Format("2006-01-02"))))

						g.Expect(err).Should(Succeed())
						g.Expect(csvLines).Should(HaveLen(2))
						// client1 -> first line
						g.Expect(csvLines[0][1]).Should(Equal("192.168.178.25"))
						g.Expect(csvLines[0][2]).Should(Equal("client1"))
						g.Expect(csvLines[0][4]).Should(Equal("reason"))
						g.Expect(csvLines[0][5]).Should(Equal("A (example.com.)"))
						g.Expect(csvLines[0][6]).Should(Equal("A (123.122.121.120)"))

						// client2 -> second line
						g.Expect(csvLines[1][1]).Should(Equal("192.168.178.26"))
						g.Expect(csvLines[1][2]).Should(Equal("client2"))
						g.Expect(csvLines[1][4]).Should(Equal("reason"))
						g.Expect(csvLines[1][5]).Should(Equal("A (example.com.)"))
						g.Expect(csvLines[1][6]).Should(Equal("A (123.122.121.120)"))
					}, "1s").Should(Succeed())

				})
			})
		})
	})

	Describe("Slow writer", func() {
		When("writer is too slow", func() {
			BeforeEach(func() {
				sutConfig = config.QueryLogConfig{
					Type:             config.QueryLogTypeNone,
					CreationAttempts: 1,
					CreationCooldown: config.Duration(time.Millisecond),
				}
			})
			It("should drop messages", func() {
				mockWriter := &SlowMockWriter{}
				sut.writer = mockWriter

				Eventually(func() int {
					_, ierr := sut.Resolve(newRequestWithClient("example.com.", dns.Type(dns.TypeA), "192.168.178.25", "client1"))
					Expect(ierr).Should(Succeed())

					return len(sut.logChan)
				}, "20s", "1µs").Should(Equal(cap(sut.logChan)))
			})
		})
	})

	Describe("Configuration output", func() {
		When("resolver is enabled", func() {
			BeforeEach(func() {
				sutConfig = config.QueryLogConfig{
					Target:           tmpDir.Path,
					Type:             config.QueryLogTypeCsvClient,
					LogRetentionDays: 0,
					CreationAttempts: 1,
					CreationCooldown: config.Duration(time.Millisecond),
				}
			})
			It("should return configuration", func() {
				c := sut.Configuration()
				Expect(len(c)).Should(BeNumerically(">", 1))
			})
		})
	})

	Describe("Clean up of query log directory", func() {
		When("fallback logger is enabled, log retention is enabled", func() {
			BeforeEach(func() {
				sutConfig = config.QueryLogConfig{
					LogRetentionDays: 7,
					Type:             config.QueryLogTypeConsole,
					CreationAttempts: 1,
					CreationCooldown: config.Duration(time.Millisecond),
				}
			})
			It("should do nothing", func() {
				sut.doCleanUp()
			})
		})
		When("log directory contains old files", func() {
			BeforeEach(func() {
				sutConfig = config.QueryLogConfig{
					Target:           tmpDir.Path,
					Type:             config.QueryLogTypeCsv,
					LogRetentionDays: 7,
					CreationAttempts: 1,
					CreationCooldown: config.Duration(time.Millisecond),
				}
			})
			It("should remove files older than defined log retention", func() {
				// create 2 files, 7 and 8 days old
				dateBefore7Days := time.Now().AddDate(0, 0, -7)
				dateBefore9Days := time.Now().AddDate(0, 0, -9)

				f1 := tmpDir.CreateEmptyFile(fmt.Sprintf("%s-test.log", dateBefore7Days.Format("2006-01-02")))
				Expect(f1.Error).Should(Succeed())

				f2 := tmpDir.CreateEmptyFile(fmt.Sprintf("%s-test.log", dateBefore9Days.Format("2006-01-02")))
				Expect(f2.Error).Should(Succeed())

				sut.doCleanUp()

				Eventually(func(g Gomega) {
					// file 1 exist
					g.Expect(f1.Stat()).Should(Succeed())

					// file 2 was deleted
					ierr2 := f2.Stat()
					g.Expect(ierr2).Should(HaveOccurred())
					g.Expect(os.IsNotExist(ierr2)).Should(BeTrue())
				}).Should(Succeed())
			})
		})
	})

	Describe("Wrong target configuration", func() {
		When("mysql database path is wrong", func() {
			BeforeEach(func() {
				sutConfig = config.QueryLogConfig{
					Target:           "dummy",
					Type:             config.QueryLogTypeMysql,
					CreationAttempts: 1,
					CreationCooldown: config.Duration(time.Millisecond),
				}
			})
			It("should use fallback", func() {
				Expect(sut.logType).Should(Equal(config.QueryLogTypeConsole))
			})
		})

		When("postgresql database path is wrong", func() {
			BeforeEach(func() {
				sutConfig = config.QueryLogConfig{
					Target:           "dummy",
					Type:             config.QueryLogTypePostgresql,
					CreationAttempts: 1,
					CreationCooldown: config.Duration(time.Millisecond),
				}
			})
			It("should use fallback", func() {
				Expect(sut.logType).Should(Equal(config.QueryLogTypeConsole))
			})
		})
	})
})

func readCsv(file string) ([][]string, error) {
	var result [][]string

	csvFile, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer csvFile.Close()

	reader := csv.NewReader(bufio.NewReader(csvFile))
	reader.Comma = '\t'

	for {
		line, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}

		result = append(result, line)
	}

	return result, nil
}
