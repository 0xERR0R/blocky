//go:build !mips && !mipsle && !mips64 && !mips64le && !loong64 && !(netbsd && !amd64) && !(openbsd && !amd64 && !arm64) && !solaris

package querylog

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/DATA-DOG/go-sqlmock"
	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	. "github.com/onsi/gomega"

	. "github.com/onsi/ginkgo/v2"
)

// countLogEntries counts rows in the log_entries table. Unlike an inline
// Find/Count it returns the query error, so Eventually surfaces a failing query
// instead of silently polling 0 until timeout.
func countLogEntries(db *gorm.DB) (int64, error) {
	var count int64

	return count, db.Model(&logEntry{}).Count(&count).Error
}

// connected waits for the writer's background connection and returns it.
func connected(w *DatabaseWriter) *gorm.DB {
	Eventually(w.db.Load, "5s").ShouldNot(BeNil())

	return w.db.Load()
}

func droppedCount(reason DropReason) float64 {
	return testutil.ToFloat64(entriesDropped.WithLabelValues(string(reason)))
}

// onInsert runs fn before each INSERT the writer issues on db.
func onInsert(db *gorm.DB, fn func(tx *gorm.DB)) {
	Expect(db.Callback().Create().Before("gorm:create").Register("test:on_insert", fn)).Should(Succeed())
}

// insertedRows returns the entries an INSERT writes, or nil for the writer's plain probe row.
func insertedRows(tx *gorm.DB) []*logEntry {
	if rows, ok := tx.Statement.Dest.(*[]*logEntry); ok {
		return *rows
	}

	return nil
}

// fileSQLite returns a SQLite database in a file. A write cut off by its context makes
// database/sql discard its connection, which would take an in-memory database with it.
func fileSQLite() gorm.Dialector {
	dialector, err := newSQLiteDialector(filepath.Join(GinkgoT().TempDir(), "querylog.db"))
	Expect(err).Should(Succeed())

	return dialector
}

// flakyDialector fails to connect the first fails times.
type flakyDialector struct {
	gorm.Dialector

	fails atomic.Int32
}

func (f *flakyDialector) Initialize(db *gorm.DB) error {
	if f.fails.Add(-1) >= 0 {
		return errors.New("connection refused")
	}

	return f.Dialector.Initialize(db)
}

var _ = Describe("DatabaseWriter", func() {
	var (
		ctx      context.Context
		cancelFn context.CancelFunc
	)
	BeforeEach(func() {
		ctx, cancelFn = context.WithCancel(context.Background())
		DeferCleanup(cancelFn)
	})
	Describe("Database query log to sqlite", func() {
		var (
			sqliteDB gorm.Dialector
			writer   *DatabaseWriter
		)
		BeforeEach(func() {
			sqliteDB = fileSQLite()
		})

		When("New log entry was created", func() {
			BeforeEach(func() {
				writer = newDatabaseWriter(ctx, fixedDialect(sqliteDB), 7, time.Millisecond, config.QueryLogTypeSqlite)
			})

			It("should be persisted in the database", func() {
				db := connected(writer)

				// one entry with now as timestamp
				writer.Write(&LogEntry{
					Start:      time.Now(),
					DurationMs: 20,
				})

				// one entry before 2 days
				writer.Write(&LogEntry{
					Start:      time.Now().AddDate(0, 0, -2),
					DurationMs: 20,
				})

				// 2 entries in the database
				Eventually(countLogEntries, "5s").WithArguments(db).Should(BeNumerically("==", 2))

				// do cleanup now
				writer.CleanUp()

				// both are within the 7-day retention
				Eventually(countLogEntries, "5s").WithArguments(db).Should(BeNumerically("==", 2))
			})
		})

		When("> 10000 Entries were created", func() {
			BeforeEach(func() {
				writer = newDatabaseWriter(ctx, fixedDialect(sqliteDB), 7, time.Millisecond, config.QueryLogTypeSqlite)
			})

			It("should be persisted in the database in bulk", func() {
				const count = 10_123

				db := connected(writer)

				for range count {
					writer.Write(&LogEntry{
						Start:      time.Now(),
						DurationMs: 20,
					})
				}

				// force write
				Expect(writer.Shutdown(ctx)).Should(Succeed())
				Expect(countLogEntries(db)).Should(BeNumerically("==", count))
			})
		})

		When("There are log entries with timestamp exceeding the retention period", func() {
			BeforeEach(func() {
				writer = newDatabaseWriter(ctx, fixedDialect(sqliteDB), 1, time.Millisecond, config.QueryLogTypeSqlite)
			})

			It("these old entries should be deleted", func() {
				db := connected(writer)

				// one entry with now as timestamp
				writer.Write(&LogEntry{
					Start:      time.Now(),
					DurationMs: 20,
				})

				// one entry before 2 days -> should be deleted
				writer.Write(&LogEntry{
					Start:      time.Now().AddDate(0, 0, -2),
					DurationMs: 20,
				})

				// 2 entries in the database
				Eventually(countLogEntries, "5s").WithArguments(db).Should(BeNumerically("==", 2))

				// do cleanup now
				writer.CleanUp()

				// now only 1 entry in the database
				Eventually(countLogEntries, "5s").WithArguments(db).Should(BeNumerically("==", 1))
			})
		})

		When("the database is slow", func() {
			It("doesn't make Write wait", func() {
				writer = newDatabaseWriter(ctx, fixedDialect(sqliteDB), 7, time.Millisecond, config.QueryLogTypeSqlite)
				db := connected(writer)

				entered := make(chan struct{})
				release := make(chan struct{})

				var blocked atomic.Bool

				blocked.Store(true)
				onInsert(db, func(*gorm.DB) {
					if blocked.CompareAndSwap(true, false) {
						close(entered)
						<-release
					}
				})

				writer.Write(&LogEntry{Start: time.Now()})
				Eventually(entered, "5s").Should(BeClosed())

				// the first INSERT is stuck in the database; more entries must still go in
				written := make(chan struct{})

				go func() {
					defer close(written)

					for range 5000 {
						writer.Write(&LogEntry{Start: time.Now()})
					}
				}()

				Eventually(written, "5s").Should(BeClosed())

				close(release)
				Expect(writer.Shutdown(ctx)).Should(Succeed())
				Expect(countLogEntries(db)).Should(BeNumerically("==", 5001))
			})
		})

		When("the database fails every write for a while", func() {
			It("keeps the batch and writes it once the database recovers", func() {
				writer = newDatabaseWriter(ctx, fixedDialect(sqliteDB), 7, time.Millisecond, config.QueryLogTypeSqlite)
				db := connected(writer)

				var (
					down     atomic.Bool
					failures atomic.Int32
				)

				down.Store(true)
				onInsert(db, func(tx *gorm.DB) {
					if down.Load() {
						failures.Add(1)
						_ = tx.AddError(errors.New("connection reset by peer"))
					}
				})

				before := droppedCount(DropReasonRejected)

				for range 3 {
					writer.Write(&LogEntry{Start: time.Now()})
				}

				Eventually(failures.Load, "5s").Should(BeNumerically(">", 0))
				down.Store(false)

				Eventually(countLogEntries, "10s").WithArguments(db).Should(BeNumerically("==", 3))
				Expect(droppedCount(DropReasonRejected) - before).Should(BeZero())
			})
		})

		When("a lone row's write fails once", func() {
			It("writes it on the second try", func() {
				writer = newDatabaseWriter(ctx, fixedDialect(sqliteDB), 7, time.Hour, config.QueryLogTypeSqlite)
				db := connected(writer)

				var failures atomic.Int32

				failures.Store(1)
				onInsert(db, func(tx *gorm.DB) {
					if insertedRows(tx) != nil && failures.Add(-1) >= 0 {
						_ = tx.AddError(errors.New("connection reset by peer"))
					}
				})

				before := droppedCount(DropReasonRejected)

				writer.Write(&LogEntry{Start: time.Now()})

				Expect(writer.Shutdown(ctx)).Should(Succeed())
				Expect(countLogEntries(db)).Should(BeNumerically("==", 1))
				Expect(droppedCount(DropReasonRejected) - before).Should(BeZero())
			})
		})

		When("a lone row's write runs out of time twice", func() {
			It("retries it instead of taking it for a refused row", func() {
				writer = newDatabaseWriter(ctx, fixedDialect(sqliteDB), 7, time.Hour, config.QueryLogTypeSqlite)
				writer.writeTimeout = 200 * time.Millisecond
				db := connected(writer)

				var slow atomic.Int32

				slow.Store(2)
				onInsert(db, func(tx *gorm.DB) {
					if insertedRows(tx) != nil && slow.Add(-1) >= 0 {
						<-tx.Statement.Context.Done() // the driver then fails the write on its own terms
					}
				})

				before := droppedCount(DropReasonRejected)

				writer.Write(&LogEntry{Start: time.Now()})

				Expect(writer.Shutdown(ctx)).Should(Succeed())
				Expect(countLogEntries(db)).Should(BeNumerically("==", 1))
				Expect(droppedCount(DropReasonRejected) - before).Should(BeZero())
			})
		})

		When("a batch is too slow to write whole", func() {
			It("splits it and writes every row", func() {
				writer = newDatabaseWriter(ctx, fixedDialect(sqliteDB), 7, time.Hour, config.QueryLogTypeSqlite)
				writer.writeTimeout = 200 * time.Millisecond
				db := connected(writer)

				onInsert(db, func(tx *gorm.DB) {
					if len(insertedRows(tx)) > 2 {
						<-tx.Statement.Context.Done()
					}
				})

				before := droppedCount(DropReasonRejected)

				for range 4 {
					writer.Write(&LogEntry{Start: time.Now()})
				}

				Expect(writer.Shutdown(ctx)).Should(Succeed())
				Expect(countLogEntries(db)).Should(BeNumerically("==", 4))
				Expect(droppedCount(DropReasonRejected) - before).Should(BeZero())
			})
		})

		When("a client name isn't valid UTF-8, holds NUL or is too long", func() {
			It("stores what every target can", func() {
				Expect(storableClientName("a\xffb\x00c\nd")).Should(Equal("a\uFFFDbcd"))
				Expect(storableClientName(strings.Repeat("é", 200))).Should(Equal(strings.Repeat("é", 191)))
				Expect(storableClientName("laptop; phone")).Should(Equal("laptop; phone"))

				writer = newDatabaseWriter(ctx, fixedDialect(sqliteDB), 7, time.Hour, config.QueryLogTypeSqlite)
				db := connected(writer)

				writer.Write(&LogEntry{Start: time.Now(), ClientNames: []string{"a\xffb\x00c"}})
				Expect(writer.Shutdown(ctx)).Should(Succeed())

				var name string
				Expect(db.Model(&logEntry{}).Select("client_name").Scan(&name).Error).Should(Succeed())
				Expect(name).Should(Equal("a\uFFFDbc"))
			})
		})

		When("a full batch is pending", func() {
			It("writes it without waiting for the flush interval", func() {
				writer = newDatabaseWriter(ctx, fixedDialect(sqliteDB), 7, time.Hour, config.QueryLogTypeSqlite)
				db := connected(writer)

				for range dbBatchSize + 1 {
					writer.Write(&LogEntry{Start: time.Now()})
				}

				Eventually(countLogEntries, "5s").WithArguments(db).Should(BeNumerically("==", dbBatchSize))
				Consistently(countLogEntries, "300ms").WithArguments(db).Should(BeNumerically("==", dbBatchSize))
			})
		})

		When("one row in a full batch is refused", func() {
			It("finds it and writes the others", func() {
				writer = newDatabaseWriter(ctx, fixedDialect(sqliteDB), 7, time.Hour, config.QueryLogTypeSqlite)
				db := connected(writer)

				onInsert(db, func(tx *gorm.DB) {
					for _, e := range insertedRows(tx) {
						if e.QuestionName == "refused.example" {
							_ = tx.AddError(errors.New("refused"))
						}
					}
				})

				before := droppedCount(DropReasonRejected)

				for i := range dbBatchSize {
					name := "ok.example"
					if i == 777 {
						name = "refused.example"
					}

					writer.Write(&LogEntry{Start: time.Now(), QuestionName: name})
				}

				Expect(writer.Shutdown(ctx)).Should(Succeed())
				Expect(countLogEntries(db)).Should(BeNumerically("==", dbBatchSize-1))
				Expect(droppedCount(DropReasonRejected) - before).Should(BeNumerically("==", 1))
			})
		})

		When("the database is unreachable at startup", func() {
			It("keeps the entries and writes them once it connects", func() {
				dialector := &flakyDialector{Dialector: sqliteDB}
				dialector.fails.Store(1)

				writer = newDatabaseWriter(ctx, fixedDialect(dialector), 7, time.Millisecond, config.QueryLogTypeSqlite)

				writer.Write(&LogEntry{Start: time.Now()})
				writer.Write(&LogEntry{Start: time.Now()})

				Eventually(countLogEntries, "5s").WithArguments(connected(writer)).Should(BeNumerically("==", 2))
			})
		})

		When("the buffer is full", func() {
			It("drops new entries and counts them", func() {
				dialector := &flakyDialector{Dialector: sqliteDB}
				dialector.fails.Store(1_000)

				writer = newDatabaseWriter(ctx, fixedDialect(dialector), 7, time.Millisecond, config.QueryLogTypeSqlite)
				writer.maxPendingBytes = 10 * (&logEntry{}).size()

				before := droppedCount(DropReasonBufferFull)

				for range 15 {
					writer.Write(&LogEntry{Start: time.Now()})
				}

				Expect(droppedCount(DropReasonBufferFull) - before).Should(BeNumerically("==", 5))
			})
		})

		When("blocky shuts down", func() {
			It("writes the pending entries", func() {
				writer = newDatabaseWriter(ctx, fixedDialect(sqliteDB), 7, time.Hour, config.QueryLogTypeSqlite)
				db := connected(writer)

				for range 3 {
					writer.Write(&LogEntry{Start: time.Now()})
				}

				// the background context ends before Shutdown, as it does in blocky's shutdown
				cancelFn()

				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				DeferCleanup(cancel)

				Expect(writer.Shutdown(shutdownCtx)).Should(Succeed())
				Expect(countLogEntries(db)).Should(BeNumerically("==", 3))

				Expect(writer.Shutdown(shutdownCtx)).Should(Succeed())
			})

			It("drops and counts them when its context is already done", func() {
				writer = newDatabaseWriter(ctx, fixedDialect(sqliteDB), 7, time.Hour, config.QueryLogTypeSqlite)
				db := connected(writer)

				for range 3 {
					writer.Write(&LogEntry{Start: time.Now()})
				}

				before := droppedCount(DropReasonShutdown)

				cancelFn()

				Expect(writer.Shutdown(ctx)).ShouldNot(Succeed())
				Expect(countLogEntries(db)).Should(BeNumerically("==", 0))
				Expect(droppedCount(DropReasonShutdown) - before).Should(BeNumerically("==", 3))
			})

			It("returns no error when nothing is left to drop", func() {
				writer = newDatabaseWriter(ctx, fixedDialect(sqliteDB), 7, time.Hour, config.QueryLogTypeSqlite)
				connected(writer)

				cancelFn()

				Expect(writer.Shutdown(ctx)).Should(Succeed())
			})

			It("counts what is left when its deadline ends while refused rows are being isolated", func() {
				writer = newDatabaseWriter(ctx, fixedDialect(sqliteDB), 7, time.Hour, config.QueryLogTypeSqlite)
				db := connected(writer)

				var plainRows atomic.Int32

				onInsert(db, func(tx *gorm.DB) {
					rows := insertedRows(tx)
					if rows == nil && plainRows.Add(1) > 1 {
						_ = tx.AddError(errors.New("connection refused")) // the database goes down after the split
					}

					for _, e := range rows {
						if e.QuestionName == "refused.example" {
							_ = tx.AddError(errors.New("refused"))
						}
					}
				})

				writer.Write(&LogEntry{Start: time.Now(), QuestionName: "refused.example"})
				writer.Write(&LogEntry{Start: time.Now(), QuestionName: "ok.example"})

				before := droppedCount(DropReasonShutdown)

				shutdownCtx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
				DeferCleanup(cancel)

				Expect(writer.Shutdown(shutdownCtx)).ShouldNot(Succeed())
				Expect(countLogEntries(db)).Should(BeNumerically("==", 0))
				Expect(droppedCount(DropReasonShutdown) - before).Should(BeNumerically("==", 2))
			})

			It("counts what is written after a Shutdown that timed out on a stuck write", func() {
				writer = newDatabaseWriter(ctx, fixedDialect(sqliteDB), 7, time.Millisecond, config.QueryLogTypeSqlite)
				db := connected(writer)

				entered := make(chan struct{})
				release := make(chan struct{})

				var stuck atomic.Bool

				stuck.Store(true)
				onInsert(db, func(*gorm.DB) {
					if stuck.CompareAndSwap(true, false) {
						close(entered)
						<-release
					}
				})

				before := droppedCount(DropReasonShutdown)

				writer.Write(&LogEntry{Start: time.Now()})
				Eventually(entered, "5s").Should(BeClosed())

				shutdownCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				DeferCleanup(cancel)

				Expect(writer.Shutdown(shutdownCtx)).Should(MatchError(context.DeadlineExceeded))

				writer.Write(&LogEntry{Start: time.Now()}) // a late DoH request, say

				close(release)
				Eventually(writer.runDone, "5s").Should(BeClosed())

				Expect(droppedCount(DropReasonShutdown) - before).Should(BeNumerically("==", 2))
			})

			It("gives up at the deadline and counts what it drops", func() {
				writer = newDatabaseWriter(ctx, fixedDialect(sqliteDB), 7, time.Hour, config.QueryLogTypeSqlite)
				db := connected(writer)

				onInsert(db, func(tx *gorm.DB) {
					_ = tx.AddError(errors.New("connection refused"))
				})

				for range 3 {
					writer.Write(&LogEntry{Start: time.Now()})
				}

				before := droppedCount(DropReasonShutdown)

				shutdownCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				DeferCleanup(cancel)

				Expect(writer.Shutdown(shutdownCtx)).ShouldNot(Succeed())
				Expect(droppedCount(DropReasonShutdown) - before).Should(BeNumerically("==", 3))
			})
		})
	})

	Describe("Database query log to sqlite file with WAL", func() {
		It("creates the file (and parent dir), enables WAL, and persists entries", func() {
			dbPath := filepath.Join(GinkgoT().TempDir(), "sub", "querylog.db") // 'sub' exercises mkdir

			w, err := NewDatabaseWriter(ctx, config.QueryLogTypeSqlite, dbPath, 7, time.Millisecond)
			Expect(err).Should(Succeed())

			db := connected(w)

			sqlDB, err := db.DB()
			Expect(err).Should(Succeed())

			// Cancel the context (stopping the periodic-flush goroutine) before closing
			// the DB, so the goroutine can't issue a write against a closed connection
			// during teardown. DeferCleanup runs LIFO, so registering this after the
			// BeforeEach's cancelFn makes it run first. (NewDatabaseWriter already pins
			// the sqlite pool to a single connection.)
			DeferCleanup(func() error {
				cancelFn()

				return sqlDB.Close()
			})

			w.Write(&LogEntry{Start: time.Now(), DurationMs: 20})

			Eventually(countLogEntries, "5s").WithArguments(db).Should(BeNumerically("==", 1))

			// the -wal sidecar only exists when journal_mode=WAL is active
			Expect(dbPath + "-wal").Should(BeAnExistingFile())
		})

		It("opens the literal path even when it contains URI-special characters", func() {
			// '?' and '#' used to truncate the path (opening a different file, '?'
			// also silently disabling WAL) and '%xx' used to be decoded into another
			// path. The DSN now percent-encodes these, so the intended file is opened.
			dbPath := filepath.Join(GinkgoT().TempDir(), "q?l#x%y.db")

			w, err := NewDatabaseWriter(ctx, config.QueryLogTypeSqlite, dbPath, 7, time.Minute)
			Expect(err).Should(Succeed())

			sqlDB, err := connected(w).DB()
			Expect(err).Should(Succeed())
			DeferCleanup(func() error {
				cancelFn()

				return sqlDB.Close()
			})

			Expect(dbPath).Should(BeAnExistingFile())
			// -wal next to the intended file confirms WAL was applied to it
			Expect(dbPath + "-wal").Should(BeAnExistingFile())
		})

		It("returns an error when the target path is empty", func() {
			_, err := NewDatabaseWriter(ctx, config.QueryLogTypeSqlite, "", 7, time.Millisecond)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("sqlite query log requires a target"))
		})
	})

	Describe("Database query log fails", func() {
		When("mysql connection parameters wrong", func() {
			It("should be log with fatal", func() {
				_, err := NewDatabaseWriter(ctx, config.QueryLogTypeMysql, "wrong param", 7, 1)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(HavePrefix("can't create database connection"))
			})
		})

		When("postgresql connection parameters wrong", func() {
			It("should be log with fatal", func() {
				_, err := NewDatabaseWriter(ctx, config.QueryLogTypePostgresql, "wrong param", 7, 1)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(HavePrefix("can't create database connection"))
			})
		})

		When("a MySQL server accepts connections but never answers", func() {
			It("gives up connecting when the context ends", func() {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				Expect(err).Should(Succeed())
				DeferCleanup(listener.Close)

				go func() { // holds each connection open and silent until the listener closes
					for {
						conn, err := listener.Accept()
						if err != nil {
							return
						}

						defer conn.Close()
					}
				}()

				dsn := "root@tcp(" + listener.Addr().String() + ")/blocky"
				connector, err := mysqldriver.MySQLDriver{}.OpenConnector(dsn)
				Expect(err).Should(Succeed())

				dialCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
				DeferCleanup(cancel)

				_, err = mysqlDialect(connector, dsn)(dialCtx)
				Expect(err).Should(MatchError(context.DeadlineExceeded))
			})
		})

		DescribeTable("a database that can't be reached",
			func(dbType config.QueryLogType, target string) {
				writer, err := NewDatabaseWriter(ctx, dbType, target, 7, time.Hour)
				Expect(err).Should(Succeed()) // connecting happens in the background

				writer.Write(&LogEntry{Start: time.Now()})
				writer.CleanUp() // skipped while disconnected
				Consistently(writer.db.Load, "200ms").Should(BeNil())

				before := droppedCount(DropReasonShutdown)

				Expect(writer.Shutdown(ctx)).Should(MatchError(ContainSubstring("never connected")))
				Expect(droppedCount(DropReasonShutdown) - before).Should(BeNumerically("==", 1))
			},
			Entry("mysql", config.QueryLogTypeMysql, "root@tcp(127.0.0.1:1)/blocky"),
			Entry("postgresql", config.QueryLogTypePostgresql, "postgres://postgres@127.0.0.1:1/blocky"),
		)

		When("invalid database type is specified", func() {
			It("should be log with fatal", func() {
				_, err := NewDatabaseWriter(ctx, config.QueryLogType(-1), "", 7, 1)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(HavePrefix("incorrect database type provided"))
			})
		})
	})

	Describe("buildSQLiteDSN", func() {
		It("builds a file URI with WAL and busy_timeout pragmas", func() {
			Expect(buildSQLiteDSN("/var/lib/blocky/querylog.db")).Should(Equal(
				"file:/var/lib/blocky/querylog.db?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"))
		})
	})

	Describe("Database initialization and migration", func() {
		var (
			db   *sql.DB
			dlc  gorm.Dialector
			mock sqlmock.Sqlmock
			err  error
		)

		When("postgres database is configured", func() {
			BeforeEach(func() {
				db, mock, err = sqlmock.New()
				Expect(err).Should(Succeed())

				dlc = postgres.New(postgres.Config{
					Conn: db,
				})
				Expect(err).Should(Succeed())

				mock.MatchExpectationsInOrder(false)
			})
			AfterEach(func() {
				Expect(mock.ExpectationsWereMet()).Should(Succeed())
			})

			It("should create the database schema automatically", func() {
				By("create table", func() {
					mock.ExpectExec(`CREATE TABLE "log_entries"`).WillReturnResult(sqlmock.NewResult(0, 0))
				})

				By("create indexes", func() {
					mock.ExpectExec(`CREATE INDEX IF NOT EXISTS "idx_log_entries_response_type"`).WillReturnResult(sqlmock.NewResult(0, 0))
					mock.ExpectExec(`CREATE INDEX IF NOT EXISTS "idx_log_entries_client_name"`).WillReturnResult(sqlmock.NewResult(0, 0))
					mock.ExpectExec(`CREATE INDEX IF NOT EXISTS "idx_log_entries_request_ts"`).WillReturnResult(sqlmock.NewResult(0, 0))
				})

				By("create postgres specific manually defined primary key", func() {
					mock.ExpectExec(`ALTER TABLE log_entries ADD column if not exists id bigserial primary key`).WillReturnResult(sqlmock.NewResult(0, 0))
				})

				_, err = openDatabase(context.Background(), dlc, config.QueryLogTypePostgresql, 1)
				Expect(err).Should(Succeed())
			})
		})

		When("mysql database is configured", func() {
			BeforeEach(func() {
				db, mock, err = sqlmock.New()
				Expect(err).Should(Succeed())

				dlc = mysql.New(mysql.Config{
					Conn:                      db,
					SkipInitializeWithVersion: true,
				})
				Expect(err).Should(Succeed())

				mock.MatchExpectationsInOrder(false)
			})
			AfterEach(func() {
				Expect(mock.ExpectationsWereMet()).Should(Succeed())
			})
			Context("Happy path", func() {
				It("should create the database schema automatically", func() {
					By("create table with indexes", func() {
						mock.ExpectExec("CREATE TABLE `log_entries`.*INDEX (`idx_log_entries_request_ts`|`idx_log_entries_client_name`|`idx_log_entries_response_type`)").WillReturnResult(sqlmock.NewResult(0, 0))
					})

					By("create mysql specific manually defined primary key", func() {
						mock.ExpectExec("ALTER TABLE `log_entries` ADD `id` INT PRIMARY KEY AUTO_INCREMENT").WillReturnResult(sqlmock.NewResult(0, 0))
					})

					_, err = openDatabase(context.Background(), dlc, config.QueryLogTypeMysql, 1)
					Expect(err).Should(Succeed())
				})
			})

			Context("primary index creation", func() {
				It("should create the database schema automatically without errors even if primary idex exists", func() {
					By("create table with indexes", func() {
						mock.ExpectExec("CREATE TABLE `log_entries`.*INDEX (`idx_log_entries_request_ts`|`idx_log_entries_client_name`|`idx_log_entries_response_type`)").WillReturnResult(sqlmock.NewResult(0, 0))
					})

					By("create mysql specific manually defined primary key should be skipped if already exists (error 1060)", func() {
						mock.ExpectExec("ALTER TABLE `log_entries` ADD `id` INT PRIMARY KEY AUTO_INCREMENT").WillReturnError(errors.New("error 1060: duplicate column name"))
					})

					_, err = openDatabase(context.Background(), dlc, config.QueryLogTypeMysql, 1)
					Expect(err).Should(Succeed())
				})

				It("should fail if manually defined index can't be created", func() {
					By("create table with indexes", func() {
						mock.ExpectExec("CREATE TABLE `log_entries`.*INDEX (`idx_log_entries_request_ts`|`idx_log_entries_client_name`|`idx_log_entries_response_type`)").WillReturnResult(sqlmock.NewResult(0, 0))
					})

					By("create mysql specific manually defined primary key should be skipped if already exists", func() {
						mock.ExpectExec("ALTER TABLE `log_entries` ADD `id` INT PRIMARY KEY AUTO_INCREMENT").WillReturnError(errors.New("error XXX: some index error"))
					})

					_, err = openDatabase(context.Background(), dlc, config.QueryLogTypeMysql, 1)
					Expect(err).Should(HaveOccurred())
					Expect(err.Error()).Should(ContainSubstring("error XXX: some index error"))
				})
			})

			Context("table can't be created", func() {
				It("should create the database schema automatically without errors", func() {
					By("create table with indexes", func() {
						mock.ExpectExec("CREATE TABLE `log_entries`").WillReturnError(errors.New("error XXX: some db error"))
					})

					_, err = openDatabase(context.Background(), dlc, config.QueryLogTypeMysql, 1)
					Expect(err).Should(HaveOccurred())
					Expect(err.Error()).Should(ContainSubstring("error XXX: some db error"))
				})
			})
		})
	})
})
