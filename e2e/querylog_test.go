package e2e

import (
	"fmt"
	"net"

	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var _ = Describe("Query logs functional tests", func() {
	var blocky, moka, database testcontainers.Container
	var db *gorm.DB
	var err error

	BeforeEach(func() {
		moka, err = createDNSMokkaContainer("moka1", `A google/NOERROR("A 1.2.3.4 123")`, `A unknown/NXDOMAIN()`)

		Expect(err).Should(Succeed())
		DeferCleanup(moka.Terminate)
	})

	Describe("Query logging into the mariaDB database", func() {
		BeforeEach(func() {
			database, err = createMariaDBContainer()
			Expect(err).Should(Succeed())
			DeferCleanup(database.Terminate)

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
			)

			Expect(err).Should(Succeed())
			DeferCleanup(blocky.Terminate)

			dbHost, dbPort, err := getContainerHostPort(database, "3306/tcp")

			Expect(err).Should(Succeed())

			dsn := fmt.Sprintf("user:user@tcp(%s)/user?charset=utf8mb4&parseTime=True&loc=Local",
				net.JoinHostPort(dbHost, dbPort))

			// database might be slow on first start, retry here if necessary
			Eventually(gorm.Open, "10s", "1s").WithArguments(mysql.Open(dsn), &gorm.Config{}).Should(Not(BeNil()))

			db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
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
			database, err = createPostgresContainer()
			Expect(err).Should(Succeed())
			DeferCleanup(database.Terminate)

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
			)

			Expect(err).Should(Succeed())
			DeferCleanup(blocky.Terminate)

			dbHost, dbPort, err := getContainerHostPort(database, "5432/tcp")
			Expect(err).Should(Succeed())

			dsn := fmt.Sprintf("postgres://user:user@%s/user", net.JoinHostPort(dbHost, dbPort))

			// database might be slow on first start, retry here if necessary
			Eventually(gorm.Open, "10s", "1s").WithArguments(postgres.Open(dsn), &gorm.Config{}).Should(Not(BeNil()))

			db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
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
