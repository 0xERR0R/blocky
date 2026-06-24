package e2e

import (
	"context"
	"net"
	"os"

	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"

	sqliteDriver "github.com/glebarez/sqlite"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
	"gorm.io/gorm"
)

// Regression test for https://github.com/0xERR0R/blocky/issues/2140
//
// With ecs.useAsClient, blocky must attribute a query to the EDNS Client Subnet client (for
// client-name lookup and query logging) rather than to the connecting forwarder - and that
// attribution must survive cache hits. The connecting test client is some docker network
// address (never 10.0.0.1), so resolving the client name to "ecsclient" and logging the
// client IP as 10.0.0.1 can only happen if the ECS subnet was adopted as the client.
var _ = Describe("ECS client identity (issue #2140)", func() {
	var (
		e2eNet  *testcontainers.DockerNetwork
		blocky  testcontainers.Container
		hostDir string
		db      *gorm.DB
		err     error
	)

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)

		_, err = createDNSMokkaContainer(ctx, "moka", e2eNet,
			`A example.com/NOERROR("A 1.2.3.4 300")`)
		Expect(err).Should(Succeed())

		// Create a host dir, world-writable so the container's non-root user can write the DB.
		hostDir, err = os.MkdirTemp("", "blocky_e2e_ecs_clientname-")
		Expect(err).Should(Succeed())
		Expect(os.Chmod(hostDir, 0o777)).Should(Succeed())
		DeferCleanup(func() error { return os.RemoveAll(hostDir) })

		blocky, err = createBlockyContainerWithBinds(ctx, e2eNet,
			[]string{hostDir + ":/data"},
			"log:",
			"  level: warn",
			"upstreams:",
			"  groups:",
			"    default:",
			"      - moka",
			// map the ECS client IP (not the forwarder) to a name, resolved in-memory
			"clientLookup:",
			"  clients:",
			"    ecsclient:",
			"      - 10.0.0.1",
			"ecs:",
			"  useAsClient: true",
			"queryLog:",
			"  type: sqlite",
			"  target: /data/querylog.db",
			"  flushInterval: 1s",
		)
		Expect(err).Should(Succeed())
	})

	It("attributes both the resolved and the cached response to the ECS client", func(ctx context.Context) {
		By("sending the same query twice, each carrying a /32 ECS option for 10.0.0.1", func() {
			for range 2 {
				msg := util.NewMsgWithQuestion("example.com.", A)
				addECSOption(msg, net.ParseIP("10.0.0.1"), 32)

				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(BeDNSRecord("example.com.", A, "1.2.3.4"))
			}
		})

		By("opening the SQLite query log written by blocky (after it created the schema)", func() {
			Eventually(func() error {
				db, err = gorm.Open(sqliteDriver.Open(
					"file:"+hostDir+"/querylog.db?_pragma=busy_timeout(5000)"), &gorm.Config{})

				return err
			}, "10s", "1s").Should(Succeed())
		})

		By("waiting for both entries to be flushed", func() {
			Eventually(countEntries, "60s", "1s").WithArguments(db).Should(BeNumerically("==", 2))
		})

		By("checking the resolved entry is attributed to the ECS client", func() {
			entries, err := queryECSEntries(db)
			Expect(err).Should(Succeed())
			Expect(entries).Should(HaveLen(2))

			Expect(entries[0]).Should(
				SatisfyAll(
					HaveField("ResponseType", "RESOLVED"),
					HaveField("ClientIP", "10.0.0.1"),
					HaveField("ClientName", "ecsclient"),
				))
		})

		By("checking the cached entry is still attributed to the ECS client", func() {
			entries, err := queryECSEntries(db)
			Expect(err).Should(Succeed())

			Expect(entries[1]).Should(
				SatisfyAll(
					HaveField("ResponseType", "CACHED"),
					HaveField("ClientIP", "10.0.0.1"),
					HaveField("ClientName", "ecsclient"),
				))
		})
	})
})

type ecsLogEntry struct {
	ClientIP     string `gorm:"column:client_ip"`
	ClientName   string `gorm:"column:client_name"`
	ResponseType string `gorm:"column:response_type"`
	QuestionName string `gorm:"column:question_name"`
}

func queryECSEntries(db *gorm.DB) ([]ecsLogEntry, error) {
	var entries []ecsLogEntry

	return entries, db.Table("log_entries").Order("request_ts").Find(&entries).Error
}
