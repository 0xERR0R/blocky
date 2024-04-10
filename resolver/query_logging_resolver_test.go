package resolver

import (
	"bufio"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/querylog"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"

	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
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
		sutConfig  config.QueryLog
		m          *mockResolver
		tmpDir     *TmpFolder
		mockRType  ResponseType
		mockAnswer *dns.Msg

		ctx      context.Context
		cancelFn context.CancelFunc
	)

	Describe("Type", func() {
		It("follows conventions", func() {
			expectValidResolverType(sut)
		})
	})

	BeforeEach(func() {
		ctx, cancelFn = context.WithCancel(context.Background())
		DeferCleanup(cancelFn)

		var err error

		sutConfig, err = config.WithDefaults[config.QueryLog]()
		Expect(err).Should(Succeed())

		mockRType = ResponseTypeRESOLVED
		mockAnswer = new(dns.Msg)
		tmpDir = NewTmpFolder("queryLoggingResolver")
	})

	JustBeforeEach(func() {
		if len(sutConfig.Fields) == 0 {
			sutConfig.SetDefaults() // not called when using a struct literal
		}

		sut = NewQueryLoggingResolver(ctx, sutConfig)

		m = &mockResolver{
			ResolveFn: func(context.Context, *Request) (*Response, error) {
				return &Response{RType: mockRType, Res: mockAnswer, Reason: "reason"}, nil
			},
		}

		m.On("Resolve", mock.Anything).Return(autoAnswer, nil)

		sut.Next(m)
	})

	Describe("IsEnabled", func() {
		It("is true", func() {
			Expect(sut.IsEnabled()).Should(BeTrue())
		})
	})

	Describe("LogConfig", func() {
		It("should log something", func() {
			logger, hook := log.NewMockEntry()

			sut.LogConfig(logger)

			Expect(hook.Calls).ShouldNot(BeEmpty())
		})
	})

	Describe("Process request", func() {
		When("Resolver has no configuration", func() {
			BeforeEach(func() {
				sutConfig = config.QueryLog{
					CreationAttempts: 1,
					CreationCooldown: config.Duration(time.Millisecond),
				}
			})
			It("should process request without query logging", func() {
				Expect(sut.Resolve(ctx, newRequest("example.com", A))).
					Should(
						SatisfyAll(
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))

				m.AssertExpectations(GinkgoT())
			})
		})

		Describe("ignore", func() {
			var ignored *log.MockLoggerHook

			JustBeforeEach(func() {
				// Stop background goroutines
				cancelFn()

				ctx, cancelFn = context.WithCancel(context.Background())
				DeferCleanup(cancelFn)

				// Capture ignored logs
				{
					var logger *logrus.Entry

					logger, ignored = log.NewMockEntry()
					ctx, _ = log.NewCtx(ctx, logger)
				}
			})

			Describe("SUDN", func() {
				JustBeforeEach(func() {
					sut.cfg.Ignore.SUDN = true
				})

				It("should not log SUDN responses", func() {
					mockRType = ResponseTypeSPECIAL

					_, err := sut.Resolve(ctx, newRequestWithClient("example.com.", A, "192.168.178.25", "client1"))
					Expect(err).Should(Succeed())

					Expect(sut.logChan).Should(BeEmpty())
					Expect(ignored.Calls).Should(HaveLen(1))
					Expect(ignored.Messages).Should(ContainElement(ContainSubstring("ignored querylog entry")))
				})

				It("should log other responses", func() {
					mockRType = ResponseTypeBLOCKED

					_, err := sut.Resolve(ctx, newRequestWithClient("example.com.", A, "192.168.178.25", "client1"))
					Expect(err).Should(Succeed())

					Expect(sut.logChan).ShouldNot(BeEmpty())
					Expect(ignored.Calls).Should(BeEmpty())
				})
			})
		})

		When("Configuration with logging per client", func() {
			BeforeEach(func() {
				sutConfig = config.QueryLog{
					Target:           tmpDir.Path,
					Type:             config.QueryLogTypeCsvClient,
					CreationAttempts: 1,
					CreationCooldown: config.Duration(time.Millisecond),
				}
				mockAnswer, _ = util.NewMsgWithAnswer("example.com.", 300, A, "123.122.121.120")
			})
			It("should create a log file per client", func() {
				By("request from client 1", func() {
					Expect(sut.Resolve(ctx, newRequestWithClient("example.com.", A, "192.168.178.25", "client1"))).
						Should(
							SatisfyAll(
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))
				})
				By("request from client 2, has name with special chars, should be escaped", func() {
					Expect(sut.Resolve(ctx, newRequestWithClient(
						"example.com.", A, "192.168.178.26", "cl/ient2\\$%&test"))).
						Should(
							SatisfyAll(
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))
				})

				m.AssertExpectations(GinkgoT())

				By("check log for client1", func() {
					Eventually(func(g Gomega) {
						csvLines, err := readCsv(tmpDir.JoinPath(
							fmt.Sprintf("%s_client1.log", time.Now().Format("2006-01-02"))))

						g.Expect(err).Should(Succeed())
						g.Expect(csvLines).ShouldNot(BeEmpty())
						g.Expect(csvLines[0][1]).Should(Equal("192.168.178.25"))
						g.Expect(csvLines[0][2]).Should(Equal("client1"))
						g.Expect(csvLines[0][4]).Should(Equal("reason"))
						g.Expect(csvLines[0][5]).Should(Equal("example.com."))
						g.Expect(csvLines[0][6]).Should(Equal("A (123.122.121.120)"))
						g.Expect(csvLines[0][7]).Should(Equal("NOERROR"))
						g.Expect(csvLines[0][8]).Should(Equal("RESOLVED"))
						g.Expect(csvLines[0][9]).Should(Equal("A"))
					}).Should(Succeed())
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
						g.Expect(csvLines[0][5]).Should(Equal("example.com."))
						g.Expect(csvLines[0][6]).Should(Equal("A (123.122.121.120)"))
						g.Expect(csvLines[0][7]).Should(Equal("NOERROR"))
						g.Expect(csvLines[0][8]).Should(Equal("RESOLVED"))
						g.Expect(csvLines[0][9]).Should(Equal("A"))
					}).Should(Succeed())
				})
			})
		})
		When("Configuration with logging in one file for all clients", func() {
			BeforeEach(func() {
				sutConfig = config.QueryLog{
					Target:           tmpDir.Path,
					Type:             config.QueryLogTypeCsv,
					CreationAttempts: 1,
					CreationCooldown: config.Duration(time.Millisecond),
				}
				mockAnswer, _ = util.NewMsgWithAnswer("example.com.", 300, A, "123.122.121.120")
			})
			It("should create one log file for all clients", func() {
				By("request from client 1", func() {
					Expect(sut.Resolve(ctx, newRequestWithClient("example.com.", A, "192.168.178.25", "client1"))).
						Should(
							SatisfyAll(
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))
				})
				By("request from client 2, has name with special chars, should be escaped", func() {
					Expect(sut.Resolve(ctx, newRequestWithClient("example.com.", A, "192.168.178.26", "client2"))).
						Should(
							SatisfyAll(
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))
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
						g.Expect(csvLines[0][5]).Should(Equal("example.com."))
						g.Expect(csvLines[0][6]).Should(Equal("A (123.122.121.120)"))
						g.Expect(csvLines[0][7]).Should(Equal("NOERROR"))
						g.Expect(csvLines[0][8]).Should(Equal("RESOLVED"))
						g.Expect(csvLines[0][9]).Should(Equal("A"))

						// client2 -> second line
						g.Expect(csvLines[1][1]).Should(Equal("192.168.178.26"))
						g.Expect(csvLines[1][2]).Should(Equal("client2"))
						g.Expect(csvLines[1][4]).Should(Equal("reason"))
						g.Expect(csvLines[1][5]).Should(Equal("example.com."))
						g.Expect(csvLines[1][6]).Should(Equal("A (123.122.121.120)"))
						g.Expect(csvLines[1][7]).Should(Equal("NOERROR"))
						g.Expect(csvLines[1][8]).Should(Equal("RESOLVED"))
						g.Expect(csvLines[1][9]).Should(Equal("A"))
					}, "1s").Should(Succeed())
				})
			})
		})
		When("Configuration with specific fields to log", func() {
			BeforeEach(func() {
				sutConfig = config.QueryLog{
					Target:           tmpDir.Path,
					Type:             config.QueryLogTypeCsv,
					CreationAttempts: 1,
					CreationCooldown: config.Duration(time.Millisecond),
					Fields:           []config.QueryLogField{config.QueryLogFieldClientIP},
				}
				mockAnswer, _ = util.NewMsgWithAnswer("example.com.", 300, A, "123.122.121.120")
			})
			It("should create one log file", func() {
				By("request from client 1", func() {
					Expect(sut.Resolve(ctx, newRequestWithClient("example.com.", A, "192.168.178.25", "client1"))).
						Should(
							SatisfyAll(
								HaveResponseType(ResponseTypeRESOLVED),
								HaveReturnCode(dns.RcodeSuccess),
							))
				})

				m.AssertExpectations(GinkgoT())

				By("check log", func() {
					Eventually(func(g Gomega) {
						csvLines, err := readCsv(tmpDir.JoinPath(
							fmt.Sprintf("%s_ALL.log", time.Now().Format("2006-01-02"))))

						g.Expect(err).Should(Succeed())
						g.Expect(csvLines).Should(HaveLen(1))

						// ip will be logged
						g.Expect(csvLines[0][1]).Should(Equal("192.168.178.25"))
						g.Expect(csvLines[0][2]).Should(Equal("none"))
						g.Expect(csvLines[0][3]).Should(Equal("0"))
						g.Expect(csvLines[0][4]).Should(Equal(""))
						g.Expect(csvLines[0][5]).Should(Equal(""))
						g.Expect(csvLines[0][6]).Should(Equal(""))
						g.Expect(csvLines[0][7]).Should(Equal(""))
						g.Expect(csvLines[0][8]).Should(Equal(""))
						g.Expect(csvLines[0][9]).Should(Equal(""))
					}, "1s").Should(Succeed())
				})
			})
		})
	})

	Describe("Slow writer", func() {
		When("writer is too slow", func() {
			BeforeEach(func() {
				sutConfig = config.QueryLog{
					Type:             config.QueryLogTypeNone,
					CreationAttempts: 1,
					CreationCooldown: config.Duration(time.Millisecond),
				}
			})
			It("should drop messages", func() {
				mockWriter := &SlowMockWriter{}
				sut.writer = mockWriter

				Eventually(func() int {
					_, ierr := sut.Resolve(ctx, newRequestWithClient("example.com.", A, "192.168.178.25", "client1"))
					Expect(ierr).Should(Succeed())

					return len(sut.logChan)
				}, "20s", "1µs").Should(Equal(cap(sut.logChan)))
			})
		})
	})

	Describe("Clean up of query log directory", func() {
		When("fallback logger is enabled, log retention is enabled", func() {
			BeforeEach(func() {
				sutConfig = config.QueryLog{
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
				sutConfig = config.QueryLog{
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
				f2 := tmpDir.CreateEmptyFile(fmt.Sprintf("%s-test.log", dateBefore9Days.Format("2006-01-02")))

				sut.doCleanUp()

				Eventually(func(g Gomega) {
					g.Expect(f1.Path).Should(BeAnExistingFile())
					g.Expect(f2.Path).ShouldNot(BeAnExistingFile())
				}).Should(Succeed())
			})
		})
	})

	Describe("Wrong target configuration", func() {
		When("mysql database path is wrong", func() {
			BeforeEach(func() {
				sutConfig = config.QueryLog{
					Target:           "dummy",
					Type:             config.QueryLogTypeMysql,
					CreationAttempts: 1,
					CreationCooldown: config.Duration(time.Millisecond),
				}
			})
			It("should use fallback", func() {
				Expect(sut.cfg.Type).Should(Equal(config.QueryLogTypeConsole))
			})
		})

		When("postgresql database path is wrong", func() {
			BeforeEach(func() {
				sutConfig = config.QueryLog{
					Target:           "dummy",
					Type:             config.QueryLogTypePostgresql,
					CreationAttempts: 1,
					CreationCooldown: config.Duration(time.Millisecond),
				}
			})
			It("should use fallback", func() {
				Expect(sut.cfg.Type).Should(Equal(config.QueryLogTypeConsole))
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
