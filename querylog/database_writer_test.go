package querylog

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	. "github.com/onsi/gomega"

	. "github.com/onsi/ginkgo/v2"
)

var err error

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
				writer, err = newDatabaseWriter(ctx, sqliteDB, 7, time.Millisecond)
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
				Eventually(func() int64 {
					var res int64
					result := writer.db.Find(&logEntry{})

					result.Count(&res)

					return res
				}, "5s").Should(BeNumerically("==", 2))

				// do cleanup now
				writer.CleanUp()

				// now only 1 entry in the database
				Eventually(func() (res int64) {
					result := writer.db.Find(&logEntry{})

					result.Count(&res)

					return res
				}, "5s").Should(BeNumerically("==", 2))
			})
		})

		When("> 10000 Entries were created", func() {
			BeforeEach(func() {
				writer, err = newDatabaseWriter(ctx, sqliteDB, 7, time.Millisecond)
				Expect(err).Should(Succeed())
			})

			It("should be persisted in the database in bulk", func() {
				const count = 10_123

				for i := 0; i < count; i++ {
					writer.Write(&LogEntry{
						Start:      time.Now(),
						DurationMs: 20,
					})
				}

				// force write
				Expect(writer.doDBWrite()).Should(Succeed())

				// 2 entries in the database
				Eventually(func() int64 {
					var res int64
					result := writer.db.Find(&logEntry{})

					result.Count(&res)

					return res
				}, "5s").Should(BeNumerically("==", count))
			})
		})

		When("There are log entries with timestamp exceeding the retention period", func() {
			BeforeEach(func() {
				writer, err = newDatabaseWriter(ctx, sqliteDB, 1, time.Millisecond)
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
				Eventually(func() int64 {
					var res int64
					result := writer.db.Find(&logEntry{})

					result.Count(&res)

					return res
				}, "5s").Should(BeNumerically("==", 2))

				// do cleanup now
				writer.CleanUp()

				// now only 1 entry in the database
				Eventually(func() (res int64) {
					result := writer.db.Find(&logEntry{})

					result.Count(&res)

					return res
				}, "5s").Should(BeNumerically("==", 1))
			})
		})
	})

	Describe("Database query log fails", func() {
		When("mysql connection parameters wrong", func() {
			It("should be log with fatal", func() {
				_, err := NewDatabaseWriter(ctx, "mysql", "wrong param", 7, 1)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(HavePrefix("can't create database connection"))
			})
		})

		When("postgresql connection parameters wrong", func() {
			It("should be log with fatal", func() {
				_, err := NewDatabaseWriter(ctx, "postgresql", "wrong param", 7, 1)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(HavePrefix("can't create database connection"))
			})
		})

		When("invalid database type is specified", func() {
			It("should be log with fatal", func() {
				_, err := NewDatabaseWriter(ctx, "invalidsql", "", 7, 1)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(HavePrefix("incorrect database type provided"))
			})
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

			//nolint:lll
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
					mock.ExpectExec(`ALTER TABLE log_entries ADD column if not exists id serial primary key`).WillReturnResult(sqlmock.NewResult(0, 0))
				})

				_, err = newDatabaseWriter(ctx, dlc, 1, time.Millisecond)
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
			//nolint:lll
			Context("Happy path", func() {
				It("should create the database schema automatically", func() {
					By("create table with indexes", func() {
						mock.ExpectExec("CREATE TABLE `log_entries`.*INDEX (`idx_log_entries_request_ts`|`idx_log_entries_client_name`|`idx_log_entries_response_type`)").WillReturnResult(sqlmock.NewResult(0, 0))
					})

					By("create mysql specific manually defined primary key", func() {
						mock.ExpectExec("ALTER TABLE `log_entries` ADD `id` INT PRIMARY KEY AUTO_INCREMENT").WillReturnResult(sqlmock.NewResult(0, 0))
					})

					_, err = newDatabaseWriter(ctx, dlc, 1, time.Millisecond)
					Expect(err).Should(Succeed())
				})
			})

			//nolint:lll
			Context("primary index creation", func() {
				It("should create the database schema automatically without errors even if primary idex exists", func() {
					By("create table with indexes", func() {
						mock.ExpectExec("CREATE TABLE `log_entries`.*INDEX (`idx_log_entries_request_ts`|`idx_log_entries_client_name`|`idx_log_entries_response_type`)").WillReturnResult(sqlmock.NewResult(0, 0))
					})

					By("create mysql specific manually defined primary key should be skipped if already exists (error 1060)", func() {
						mock.ExpectExec("ALTER TABLE `log_entries` ADD `id` INT PRIMARY KEY AUTO_INCREMENT").WillReturnError(fmt.Errorf("error 1060: duplicate column name"))
					})

					_, err = newDatabaseWriter(ctx, dlc, 1, time.Millisecond)
					Expect(err).Should(Succeed())
				})

				It("should fail if manually defined index can't be created", func() {
					By("create table with indexes", func() {
						mock.ExpectExec("CREATE TABLE `log_entries`.*INDEX (`idx_log_entries_request_ts`|`idx_log_entries_client_name`|`idx_log_entries_response_type`)").WillReturnResult(sqlmock.NewResult(0, 0))
					})

					By("create mysql specific manually defined primary key should be skipped if already exists", func() {
						mock.ExpectExec("ALTER TABLE `log_entries` ADD `id` INT PRIMARY KEY AUTO_INCREMENT").WillReturnError(fmt.Errorf("error XXX: some index error"))
					})

					_, err = newDatabaseWriter(ctx, dlc, 1, time.Millisecond)
					Expect(err).Should(HaveOccurred())
					Expect(err.Error()).Should(ContainSubstring("can't perform auto migration: error XXX: some index error"))
				})
			})

			Context("table can't be created", func() {
				It("should create the database schema automatically without errors", func() {
					By("create table with indexes", func() {
						mock.ExpectExec("CREATE TABLE `log_entries`").WillReturnError(fmt.Errorf("error XXX: some db error"))
					})

					_, err = newDatabaseWriter(ctx, dlc, 1, time.Millisecond)
					Expect(err).Should(HaveOccurred())
					Expect(err.Error()).Should(ContainSubstring("can't perform auto migration: error XXX: some db error"))
				})
			})
		})
	})
})
