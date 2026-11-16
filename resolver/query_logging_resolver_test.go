package resolver

import (
	"bufio"
	"context"
	"encoding/csv"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/metrics"
	"github.com/0xERR0R/blocky/querylog"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"

	"github.com/0xERR0R/blocky/cache/stringcache"
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

	time.Sleep(100 * time.Millisecond)
}

func (m *SlowMockWriter) CleanUp() {
}

type ShutdownRecordingWriter struct {
	entries  []*querylog.LogEntry
	shutdown bool
}

func (m *ShutdownRecordingWriter) Write(entry *querylog.LogEntry) {
	m.entries = append(m.entries, entry)
}

func (m *ShutdownRecordingWriter) CleanUp() {
}

func (m *ShutdownRecordingWriter) Shutdown(context.Context) error {
	m.shutdown = true

	return nil
}

func droppedEntries(reason querylog.DropReason) float64 {
	families, err := metrics.Reg.Gather()
	Expect(err).Should(Succeed())

	for _, family := range families {
		if family.GetName() != "blocky_query_log_entries_dropped_total" {
			continue
		}

		for _, m := range family.GetMetric() {
			if m.GetLabel()[0].GetValue() == string(reason) {
				return m.GetCounter().GetValue()
			}
		}
	}

	return 0
}

var _ = Describe("QueryLoggingResolver", func() {
	var (
		sut        *QueryLoggingResolver
		sutConfig  config.QueryLog
		err        error
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

		sut, err = NewQueryLoggingResolver(ctx, sutConfig)
		Expect(err).Should(Succeed())

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

		When("type is none", func() {
			BeforeEach(func() {
				sutConfig = config.QueryLog{
					Type:             config.QueryLogTypeNone,
					CreationAttempts: 1,
					CreationCooldown: config.Duration(time.Millisecond),
				}
			})
			It("should pass the request through without building a log entry", func() {
				Expect(sut.Resolve(ctx, newRequestWithClient("example.com.", A, "192.168.178.25", "client1"))).
					Should(
						SatisfyAll(
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))

				m.AssertExpectations(GinkgoT())
				Expect(sut.logChan).Should(BeEmpty())
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

			Describe("Domains", func() {
				BeforeEach(func() {
					sutConfig.Ignore.Domains = []string{"ignored.example.com", "*.noisy.lan"}
				})

				It("should not log a matching exact domain", func() {
					_, err := sut.Resolve(ctx,
						newRequestWithClient("ignored.example.com.", A, "192.168.178.25", "client1"))
					Expect(err).Should(Succeed())

					Expect(sut.logChan).Should(BeEmpty())
					Expect(ignored.Messages).Should(ContainElement(ContainSubstring("ignored querylog entry")))
				})

				It("should not log a matching wildcard domain", func() {
					_, err := sut.Resolve(ctx,
						newRequestWithClient("host.noisy.lan.", A, "192.168.178.25", "client1"))
					Expect(err).Should(Succeed())

					Expect(sut.logChan).Should(BeEmpty())
					Expect(ignored.Messages).Should(ContainElement(ContainSubstring("ignored querylog entry")))
				})

				It("should log a non-matching domain", func() {
					_, err := sut.Resolve(ctx,
						newRequestWithClient("example.com.", A, "192.168.178.25", "client1"))
					Expect(err).Should(Succeed())

					Expect(sut.logChan).ShouldNot(BeEmpty())
					Expect(ignored.Calls).Should(BeEmpty())
				})
			})

			Describe("Clients", func() {
				BeforeEach(func() {
					sutConfig.Ignore.Clients = []string{"192.168.178.1", "10.0.0.0/24", "printer", "*-ap"}
				})

				DescribeTable("should not log queries from a matching client",
					func(ip string, names ...string) {
						_, err := sut.Resolve(ctx, newRequestWithClient("example.com.", A, ip, names...))
						Expect(err).Should(Succeed())

						Expect(sut.logChan).Should(BeEmpty())
						Expect(ignored.Messages).Should(ContainElement(ContainSubstring("ignored querylog entry")))
					},
					Entry("by IP", "192.168.178.1", "router"),
					Entry("by CIDR", "10.0.0.7", "laptop"),
					Entry("by client name, case-insensitive", "192.168.178.30", "Printer"),
					Entry("by client name wildcard", "192.168.178.31", "kitchen-ap"),
					Entry("by any of the client names", "192.168.178.32", "laptop", "printer"),
				)

				It("should log queries from other clients", func() {
					_, err := sut.Resolve(ctx,
						newRequestWithClient("example.com.", A, "192.168.178.25", "client1"))
					Expect(err).Should(Succeed())

					Expect(sut.logChan).ShouldNot(BeEmpty())
					Expect(ignored.Calls).Should(BeEmpty())
				})
			})
		})

		When("Configuration with logging per client", func() {
			BeforeEach(func() {
				sutConfig = config.QueryLog{
					Target:           config.Secret(tmpDir.Path),
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
							time.Now().Format("2006-01-02") + "_client1.log"))

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
							time.Now().Format("2006-01-02") + "_cl_ient2_test.log"))

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
					Target:           config.Secret(tmpDir.Path),
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
							time.Now().Format("2006-01-02") + "_ALL.log"))

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
					Target:           config.Secret(tmpDir.Path),
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
							time.Now().Format("2006-01-02") + "_ALL.log"))

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
				// Console keeps the resolver enabled (None now short-circuits) without
				// needing a target; the writer is replaced with SlowMockWriter below.
				sutConfig = config.QueryLog{
					Type:             config.QueryLogTypeConsole,
					CreationAttempts: 1,
					CreationCooldown: config.Duration(time.Millisecond),
				}
			})
			It("should drop messages and count them", func() {
				mockWriter := &SlowMockWriter{}
				sut.writer = mockWriter

				before := droppedEntries(querylog.DropReasonQueueFull)

				Eventually(func() float64 {
					_, ierr := sut.Resolve(ctx, newRequestWithClient("example.com.", A, "192.168.178.25", "client1"))
					Expect(ierr).Should(Succeed())

					return droppedEntries(querylog.DropReasonQueueFull) - before
				}, "3s", "1µs").Should(BeNumerically(">", 0))
			})
		})
	})

	Describe("Shutdown", func() {
		BeforeEach(func() {
			sutConfig = config.QueryLog{
				Type:             config.QueryLogTypeConsole,
				CreationAttempts: 1,
				CreationCooldown: config.Duration(time.Millisecond),
			}
		})
		// queue fills the queue once the background context has ended, as in blocky's
		// shutdown, where DNS still answers then.
		queue := func(n int) {
			cancelFn()
			Eventually(sut.writeLogDone).Should(BeClosed())

			for range n {
				_, ierr := sut.Resolve(context.Background(), newRequestWithClient("example.com.", A, "192.168.178.25", "client1"))
				Expect(ierr).Should(Succeed())
			}
		}

		It("writes the queued entries, then shuts the writer down", func() {
			writer := &ShutdownRecordingWriter{}
			sut.writer = writer

			queue(50)

			Expect(sut.Shutdown(context.Background())).Should(Succeed())
			Expect(writer.entries).Should(HaveLen(50))
			Expect(writer.shutdown).Should(BeTrue())
		})

		It("stops at the deadline and counts what is left in the queue", func() {
			writer := &ShutdownRecordingWriter{}
			sut.writer = writer

			queue(20)

			before := droppedEntries(querylog.DropReasonShutdown)

			Expect(sut.Shutdown(ctx)).Should(MatchError(context.Canceled)) // ctx is done already
			Expect(writer.entries).Should(BeEmpty())
			Expect(writer.shutdown).Should(BeTrue())
			Expect(droppedEntries(querylog.DropReasonShutdown) - before).Should(BeNumerically("==", 20))
		})

		It("leaves a writer that holds nothing in memory alone", func() {
			queue(3) // the console writer

			Expect(sut.Shutdown(context.Background())).Should(Succeed())
			Expect(sut.logChan).Should(HaveLen(3))
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
					Target:           config.Secret(tmpDir.Path),
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

				f1 := tmpDir.CreateEmptyFile(dateBefore7Days.Format("2006-01-02") + "-test.log")
				f2 := tmpDir.CreateEmptyFile(dateBefore9Days.Format("2006-01-02") + "-test.log")

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

		When("dnstap target is invalid", func() {
			BeforeEach(func() {
				sutConfig = config.QueryLog{
					Target:           "not-a-valid-target",
					Type:             config.QueryLogTypeDnstap,
					CreationAttempts: 1,
					CreationCooldown: config.Duration(time.Millisecond),
				}
			})
			It("should use fallback", func() {
				Expect(sut.cfg.Type).Should(Equal(config.QueryLogTypeConsole))
			})
		})
	})

	Describe("GetQueryLoggingWriter", func() {
		It("creates a database writer", func() {
			dbPath := filepath.Join(GinkgoT().TempDir(), "querylog.db")

			writer, err := GetQueryLoggingWriter(ctx, config.QueryLog{
				Type:          config.QueryLogTypeSqlite,
				Target:        config.Secret(dbPath),
				FlushInterval: config.Duration(time.Millisecond),
			}, "test-instance")

			Expect(err).Should(Succeed())
			Expect(writer).ShouldNot(BeNil())
			Expect(writer).Should(BeAssignableToTypeOf(&querylog.DatabaseWriter{}))

			// it connects in the background: stop it before the directory is removed
			DeferCleanup(func() { _ = writer.(*querylog.DatabaseWriter).Shutdown(ctx) })
		})

		It("creates a dnstap writer", func() {
			sockPath := filepath.Join(GinkgoT().TempDir(), "dnstap.sock")
			writer, err := GetQueryLoggingWriter(ctx, config.QueryLog{
				Type:          config.QueryLogTypeDnstap,
				Target:        config.Secret("unix:" + sockPath),
				FlushInterval: config.Duration(time.Millisecond),
			}, "test-instance")
			Expect(err).Should(Succeed())
			Expect(writer).ShouldNot(BeNil())
			Expect(writer).Should(BeAssignableToTypeOf(&querylog.DnstapWriter{}))
			Expect(writer.(*querylog.DnstapWriter).Close()).Should(Succeed())
		})
	})

	Describe("Hostname function tests", func() {
		It("should use the given file if it exists", func() {
			expected := "TestName"
			tmpFile := NewTmpFolder("hostname").CreateStringFile("filetest1", expected+" \n")

			Expect(readInstanceID(tmpFile.Path)).Should(Equal(expected))
		})

		It("should fallback to os.Hostname", func() {
			expected, err := os.Hostname()
			Expect(err).Should(Succeed())

			Expect(readInstanceID("/var/empty/nonexistent")).Should(Equal(expected))
		})
	})

	Describe("newIgnoreDomainsMatcher", func() {
		It("returns nil for an empty list", func() {
			logger, _ := log.NewMockEntry()
			Expect(newIgnoreDomainsMatcher(nil, logger)).Should(BeNil())
		})

		It("matches exact, wildcard and regex entries", func() {
			logger, _ := log.NewMockEntry()
			matcher := newIgnoreDomainsMatcher(
				[]string{"example.com", "*.lan", "/\\.arpa$/"}, logger)
			Expect(matcher).ShouldNot(BeNil())

			groups := []string{queryLogIgnoreGroup}
			Expect(matcher.Contains("example.com", groups)).ShouldNot(BeEmpty())
			Expect(matcher.Contains("host.lan", groups)).ShouldNot(BeEmpty())
			Expect(matcher.Contains("1.0.0.10.in-addr.arpa", groups)).ShouldNot(BeEmpty())
			Expect(matcher.Contains("other.com", groups)).Should(BeEmpty())
		})

		It("warns and skips an invalid entry but keeps valid ones", func() {
			logger, hook := log.NewMockEntry()
			matcher := newIgnoreDomainsMatcher(
				[]string{"/[invalid(/", "example.com"}, logger)

			Expect(matcher).ShouldNot(BeNil())
			Expect(matcher.Contains("example.com", []string{queryLogIgnoreGroup})).ShouldNot(BeEmpty())
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("invalid")))
		})

		It("warns and skips a lone slash entry without panicking", func() {
			logger, hook := log.NewMockEntry()

			var matcher stringcache.GroupedStringCache
			Expect(func() {
				matcher = newIgnoreDomainsMatcher([]string{"/", "example.com"}, logger)
			}).ShouldNot(Panic())

			Expect(matcher.Contains("example.com", []string{queryLogIgnoreGroup})).ShouldNot(BeEmpty())
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("invalid")))
		})

		It("warns and skips empty regex entries instead of matching every domain", func() {
			logger, hook := log.NewMockEntry()

			matcher := newIgnoreDomainsMatcher([]string{"//", "/ /", "example.com"}, logger)
			Expect(matcher).ShouldNot(BeNil())

			groups := []string{queryLogIgnoreGroup}
			// an empty regex would match everything; the entries must be rejected
			Expect(matcher.Contains("unrelated.example.net", groups)).Should(BeEmpty())
			Expect(matcher.Contains("example.com", groups)).ShouldNot(BeEmpty())
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("invalid")))
		})
	})

	Describe("newIgnoredClients", func() {
		It("returns nil for an empty list", func() {
			logger, _ := log.NewMockEntry()
			Expect(newIgnoredClients(nil, logger)).Should(BeNil())
		})

		It("matches IPs, CIDRs, client names and wildcards", func() {
			logger, _ := log.NewMockEntry()
			m := newIgnoredClients([]string{"192.0.2.10", "2001:DB8::1", "192.0.2.64/28", " NAS ", "*-ap"}, logger)

			Expect(m.matches(newRequestWithClient("example.com.", A, "192.0.2.10"))).Should(BeTrue())
			Expect(m.matches(newRequestWithClient("example.com.", A, "::ffff:192.0.2.10"))).Should(BeTrue())
			Expect(m.matches(newRequestWithClient("example.com.", A, "2001:db8::1"))).Should(BeTrue())
			Expect(m.matches(newRequestWithClient("example.com.", A, "192.0.2.70"))).Should(BeTrue())
			Expect(m.matches(newRequestWithClient("example.com.", A, "192.0.2.80", "nas"))).Should(BeTrue())
			Expect(m.matches(newRequestWithClient("example.com.", A, "192.0.2.80", "Office-AP"))).Should(BeTrue())

			Expect(m.matches(newRequestWithClient("example.com.", A, "192.0.2.80", "laptop"))).Should(BeFalse())
			Expect(m.matches(newRequestWithClient("example.com.", A, "192.0.2.11"))).Should(BeFalse())
		})

		It("matches a CIDR entry only against the client IP", func() {
			logger, _ := log.NewMockEntry()
			m := newIgnoredClients([]string{"192.0.2.0/24"}, logger)

			Expect(m.matches(newRequestWithClient("example.com.", A, "198.51.100.1", "192.0.2.0/24"))).Should(BeFalse())
		})

		It("warns and skips invalid entries but keeps valid ones", func() {
			logger, hook := log.NewMockEntry()
			m := newIgnoredClients([]string{"[", "  ", "printer"}, logger)

			Expect(m.globs).Should(BeEmpty())
			Expect(m.matches(newRequestWithClient("example.com.", A, "192.0.2.1", "printer"))).Should(BeTrue())
			Expect(hook.Messages).Should(HaveEach(ContainSubstring("invalid")))
			Expect(hook.Messages).Should(HaveLen(2))
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
