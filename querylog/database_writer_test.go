package querylog

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/DATA-DOG/go-sqlmock"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	. "github.com/onsi/gomega"

	. "github.com/onsi/ginkgo/v2"
)

var err error

// countLogEntries counts rows in the log_entries table. Unlike an inline
// Find/Count it returns the query error, so Eventually surfaces a failing query
// instead of silently polling 0 until timeout.
func countLogEntries(db *gorm.DB) (int64, error) {
	var count int64

	return count, db.Model(&logEntry{}).Count(&count).Error
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
			sqliteDB = sqlite.Open("file::memory:")
		})

		When("New log entry was created", func() {
			BeforeEach(func() {
				writer, err = newDatabaseWriter(ctx, sqliteDB, 7, time.Millisecond, config.QueryLogTypeSqlite)
				Expect(err).Should(Succeed())

				db, err := writer.db.DB()
				Expect(err).Should(Succeed())
				// sometimes db migration takes some time to makes changes visible to other db sessions
				// this leads in sporadic errors -> first query log write attempt fails because db table does not exist
				// to avoid it, use only 1 connection for test
				db.SetMaxOpenConns(1)
				DeferCleanup(db.Close)
			})

			It("should be persisted in the database", func() {
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
				Eventually(countLogEntries, "5s").WithArguments(writer.db).Should(BeNumerically("==", 2))

				// do cleanup now
				writer.CleanUp()

				// now only 1 entry in the database
				Eventually(countLogEntries, "5s").WithArguments(writer.db).Should(BeNumerically("==", 2))
			})
		})

		When("> 10000 Entries were created", func() {
			BeforeEach(func() {
				writer, err = newDatabaseWriter(ctx, sqliteDB, 7, time.Millisecond, config.QueryLogTypeSqlite)
				Expect(err).Should(Succeed())
			})

			It("should be persisted in the database in bulk", func() {
				const count = 10_123

				for range count {
					writer.Write(&LogEntry{
						Start:      time.Now(),
						DurationMs: 20,
					})
				}

				// force write
				Expect(writer.doDBWrite()).Should(Succeed())

				// 2 entries in the database
				Eventually(countLogEntries, "5s").WithArguments(writer.db).Should(BeNumerically("==", count))
			})
		})

		When("There are log entries with timestamp exceeding the retention period", func() {
			BeforeEach(func() {
				writer, err = newDatabaseWriter(ctx, sqliteDB, 1, time.Millisecond, config.QueryLogTypeSqlite)
				Expect(err).Should(Succeed())
			})

			It("these old entries should be deleted", func() {
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

				// force write
				Expect(writer.doDBWrite()).Should(Succeed())

				// 2 entries in the database
				Eventually(countLogEntries, "5s").WithArguments(writer.db).Should(BeNumerically("==", 2))

				// do cleanup now
				writer.CleanUp()

				// now only 1 entry in the database
				Eventually(countLogEntries, "5s").WithArguments(writer.db).Should(BeNumerically("==", 1))
			})
		})
	})

	Describe("Database query log to sqlite file with WAL", func() {
		It("creates the file (and parent dir), enables WAL, and persists entries", func() {
			dbPath := filepath.Join(GinkgoT().TempDir(), "sub", "querylog.db") // 'sub' exercises mkdir

			w, err := NewDatabaseWriter(ctx, config.QueryLogTypeSqlite, dbPath, 7, time.Millisecond)
			Expect(err).Should(Succeed())

			sqlDB, err := w.db.DB()
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

			Eventually(countLogEntries, "5s").WithArguments(w.db).Should(BeNumerically("==", 1))

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

			sqlDB, err := w.db.DB()
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

				_, err = newDatabaseWriter(ctx, dlc, 1, time.Millisecond, config.QueryLogTypePostgresql)
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

					_, err = newDatabaseWriter(ctx, dlc, 1, time.Millisecond, config.QueryLogTypeMysql)
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

					_, err = newDatabaseWriter(ctx, dlc, 1, time.Millisecond, config.QueryLogTypeMysql)
					Expect(err).Should(Succeed())
				})

				It("should fail if manually defined index can't be created", func() {
					By("create table with indexes", func() {
						mock.ExpectExec("CREATE TABLE `log_entries`.*INDEX (`idx_log_entries_request_ts`|`idx_log_entries_client_name`|`idx_log_entries_response_type`)").WillReturnResult(sqlmock.NewResult(0, 0))
					})

					By("create mysql specific manually defined primary key should be skipped if already exists", func() {
						mock.ExpectExec("ALTER TABLE `log_entries` ADD `id` INT PRIMARY KEY AUTO_INCREMENT").WillReturnError(errors.New("error XXX: some index error"))
					})

					_, err = newDatabaseWriter(ctx, dlc, 1, time.Millisecond, config.QueryLogTypeMysql)
					Expect(err).Should(HaveOccurred())
					Expect(err.Error()).Should(ContainSubstring("error XXX: some index error"))
				})
			})

			Context("table can't be created", func() {
				It("should create the database schema automatically without errors", func() {
					By("create table with indexes", func() {
						mock.ExpectExec("CREATE TABLE `log_entries`").WillReturnError(errors.New("error XXX: some db error"))
					})

					_, err = newDatabaseWriter(ctx, dlc, 1, time.Millisecond, config.QueryLogTypeMysql)
					Expect(err).Should(HaveOccurred())
					Expect(err.Error()).Should(ContainSubstring("error XXX: some db error"))
				})
			})
		})
	})
})
