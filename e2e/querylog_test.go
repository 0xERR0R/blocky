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
	var blocky testcontainers.Container
	var postgresDB *postgres.PostgresContainer
	var mariaDB *mariadb.MariaDBContainer
	var db *gorm.DB
	var err error

	BeforeEach(func(ctx context.Context) {
		_, err = createDNSMokkaContainer(ctx, "moka1", `A google/NOERROR("A 1.2.3.4 123")`, `A unknown/NXDOMAIN()`)
		Expect(err).Should(Succeed())
	})

	Describe("Query logging into the mariaDB database", func() {
		BeforeEach(func(ctx context.Context) {
			mariaDB, err = createMariaDBContainer(ctx)
			Expect(err).Should(Succeed())

			blocky, err = createBlockyContainer(ctx, tmpDir,
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

			connectionString, err := mariaDB.ConnectionString(ctx,
				"tls=false", "charset=utf8mb4", "parseTime=True", "loc=Local")
			Expect(err).Should(Succeed())

			// database might be slow on first start, retry here if necessary
			Eventually(gorm.Open, "10s", "1s").
				WithArguments(mysqlDriver.Open(connectionString), &gorm.Config{}).ShouldNot(BeNil())

			db, err = gorm.Open(mysqlDriver.Open(connectionString), &gorm.Config{})
			Expect(err).Should(Succeed())

			Eventually(countEntries).WithArguments(db).Should(BeNumerically("==", 0))
		})
		When("Some queries were performed", func() {
			It("Should store query log in the mariaDB database", func(ctx context.Context) {
				By("Performing 2 queries", func() {
					Expect(doDNSRequest(ctx, blocky,
						util.NewMsgWithQuestion("google.de.", dns.Type(dns.TypeA)))).ShouldNot(BeNil())
					Expect(doDNSRequest(ctx, blocky,
						util.NewMsgWithQuestion("unknown.domain.", dns.Type(dns.TypeA)))).ShouldNot(BeNil())
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
		BeforeEach(func(ctx context.Context) {
			postgresDB, err = createPostgresContainer(ctx)
			Expect(err).Should(Succeed())

			blocky, err = createBlockyContainer(ctx, tmpDir,
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

			connectionString, err := postgresDB.ConnectionString(ctx, "sslmode=disable")
			Expect(err).Should(Succeed())

			// database might be slow on first start, retry here if necessary
			Eventually(gorm.Open, "10s", "1s").
				WithArguments(postgresDriver.Open(connectionString), &gorm.Config{}).ShouldNot(BeNil())

			db, err = gorm.Open(postgresDriver.Open(connectionString), &gorm.Config{})
			Expect(err).Should(Succeed())

			Eventually(countEntries).WithArguments(db).Should(BeNumerically("==", 0))
		})
		When("Some queries were performed", func() {
			msg := util.NewMsgWithQuestion("google.de.", dns.Type(dns.TypeA))
			It("Should store query log in the postgres database", func(ctx context.Context) {
				By("Performing 2 queries", func() {
					Expect(doDNSRequest(ctx, blocky, msg)).ShouldNot(BeNil())
					Expect(doDNSRequest(ctx, blocky, msg)).ShouldNot(BeNil())
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
