package e2e

import (
	"context"

	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mariadb"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	mysqlDriver "gorm.io/driver/mysql"
	postgresDriver "gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var _ = Describe("Query logs functional tests", func() {
	var blocky, moka testcontainers.Container
	var postgresDB *postgres.PostgresContainer
	var mariaDB *mariadb.MariaDBContainer
	var db *gorm.DB
	var err error

	BeforeEach(func() {
		moka, err = createDNSMokkaContainer("moka1", `A google/NOERROR("A 1.2.3.4 123")`, `A unknown/NXDOMAIN()`)

		Expect(err).Should(Succeed())
		DeferCleanup(moka.Terminate)
	})

	Describe("Query logging into the mariaDB database", func() {
		BeforeEach(func() {
			mariaDB, err = createMariaDBContainer()
			Expect(err).Should(Succeed())
			DeferCleanup(mariaDB.Terminate)

			blocky, err = createBlockyContainer(tmpDir,
				"log:",
				"  level: warn",
				"upstreams:",
				"  groups:",
				"    default:",
				"      - moka1",
				"queryLog:",
				"  type: mysql",
				"  target: user:user@tcp(mariaDB:3306)/user?charset=utf8mb4&parseTime=True&loc=Local",
				"  flushInterval: 1s",
			)

			Expect(err).Should(Succeed())
			DeferCleanup(blocky.Terminate)

			Expect(err).Should(Succeed())

			connectionString, err := mariaDB.ConnectionString(context.Background(),
				"tls=false", "charset=utf8mb4", "parseTime=True", "loc=Local")
			Expect(err).Should(Succeed())

			// database might be slow on first start, retry here if necessary
			Eventually(gorm.Open, "10s", "1s").
				WithArguments(mysqlDriver.Open(connectionString), &gorm.Config{}).Should(Not(BeNil()))

			db, err = gorm.Open(mysqlDriver.Open(connectionString), &gorm.Config{})
			Expect(err).Should(Succeed())

			Eventually(countEntries).WithArguments(db).Should(BeNumerically("==", 0))
		})
		When("Some queries were performed", func() {
			It("Should store query log in the mariaDB database", func() {
				By("Performing 2 queries", func() {
					Expect(doDNSRequest(blocky, util.NewMsgWithQuestion("google.de.", dns.Type(dns.TypeA)))).Should(Not(BeNil()))
					Expect(doDNSRequest(blocky, util.NewMsgWithQuestion("unknown.domain.", dns.Type(dns.TypeA)))).Should(Not(BeNil()))
				})

				By("check entries count asynchronously, since blocky flushes log entries in bulk", func() {
					Eventually(countEntries, "60s", "1s").WithArguments(db).Should(BeNumerically("==", 2))
				})

				By("check entry content", func() {
					entries, err := queryEntries(db)
					Expect(err).Should(Succeed())

					Expect(entries).Should(HaveLen(2))

					Expect(entries[0]).
						Should(
							SatisfyAll(
								HaveField("ResponseType", "RESOLVED"),
								HaveField("QuestionType", "A"),
								HaveField("QuestionName", "google.de"),
								HaveField("Answer", "A (1.2.3.4)"),
								HaveField("ResponseCode", "NOERROR"),
							))

					Expect(entries[1]).
						Should(
							SatisfyAll(
								HaveField("ResponseType", "RESOLVED"),
								HaveField("QuestionType", "A"),
								HaveField("QuestionName", "unknown.domain"),
								HaveField("Answer", ""),
								HaveField("ResponseCode", "NXDOMAIN"),
							))
				})
			})
		})
	})

	Describe("Query logging into the postgres database", func() {
		BeforeEach(func() {
			postgresDB, err = createPostgresContainer()
			Expect(err).Should(Succeed())
			DeferCleanup(postgresDB.Terminate)

			blocky, err = createBlockyContainer(tmpDir,
				"log:",
				"  level: warn",
				"upstreams:",
				"  groups:",
				"    default:",
				"      - moka1",
				"queryLog:",
				"  type: postgresql",
				"  target: postgres://user:user@postgres:5432/user",
				"  flushInterval: 1s",
			)

			Expect(err).Should(Succeed())
			DeferCleanup(blocky.Terminate)

			connectionString, err := postgresDB.ConnectionString(context.Background(), "sslmode=disable")
			Expect(err).Should(Succeed())

			// database might be slow on first start, retry here if necessary
			Eventually(gorm.Open, "10s", "1s").
				WithArguments(postgresDriver.Open(connectionString), &gorm.Config{}).Should(Not(BeNil()))

			db, err = gorm.Open(postgresDriver.Open(connectionString), &gorm.Config{})
			Expect(err).Should(Succeed())

			Eventually(countEntries).WithArguments(db).Should(BeNumerically("==", 0))
		})
		When("Some queries were performed", func() {
			msg := util.NewMsgWithQuestion("google.de.", dns.Type(dns.TypeA))
			It("Should store query log in the postgres database", func() {
				By("Performing 2 queries", func() {
					Expect(doDNSRequest(blocky, msg)).Should(Not(BeNil()))
					Expect(doDNSRequest(blocky, msg)).Should(Not(BeNil()))
				})

				By("check entries count asynchronously, since blocky flushes log entries in bulk", func() {
					Eventually(countEntries, "60s", "1s").WithArguments(db).Should(BeNumerically("==", 2))
				})

				By("check entry content", func() {
					entries, err := queryEntries(db)
					Expect(err).Should(Succeed())

					Expect(entries).Should(HaveLen(2))

					Expect(entries[0]).
						Should(
							SatisfyAll(
								HaveField("ResponseType", "RESOLVED"),
								HaveField("QuestionType", "A"),
								HaveField("QuestionName", "google.de"),
								HaveField("Answer", "A (1.2.3.4)"),
								HaveField("ResponseCode", "NOERROR"),
							))

					Expect(entries[1]).
						Should(
							SatisfyAll(
								HaveField("ResponseType", "CACHED"),
								HaveField("QuestionType", "A"),
								HaveField("QuestionName", "google.de"),
								HaveField("Answer", "A (1.2.3.4)"),
								HaveField("ResponseCode", "NOERROR"),
							))
				})
			})
		})
	})
})

type logEntry struct {
	ResponseType string
	QuestionType string
	QuestionName string
	Answer       string
	ResponseCode string
}

func queryEntries(db *gorm.DB) ([]logEntry, error) {
	var entries []logEntry

	return entries, db.Find(&entries).Order("request_ts DESC").Error
}

func countEntries(db *gorm.DB) (int64, error) {
	var cnt int64

	return cnt, db.Table("log_entries").Count(&cnt).Error
}
