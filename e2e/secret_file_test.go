package e2e

import (
	"context"
	"os"
	"strings"

	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"

	// goredis is the client lib; redismod is the testcontainers module —
	// aliased to avoid the two "redis" package names colliding.
	goredis "github.com/go-redis/redis/v8"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
	redismod "github.com/testcontainers/testcontainers-go/modules/redis"
)

var _ = Describe("Secret file config", func() {
	var (
		e2eNet      *testcontainers.DockerNetwork
		blocky      testcontainers.Container
		redisDB     *redismod.RedisContainer
		redisClient *goredis.Client
		err         error
	)

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)

		redisDB, err = createRedisContainerWithPassword(ctx, e2eNet)
		Expect(err).Should(Succeed())

		_, err = createDNSMokkaContainer(ctx, "moka1", e2eNet, `A google/NOERROR("A 1.2.3.4 123")`)
		Expect(err).Should(Succeed())

		redisConn, err := redisDB.ConnectionString(ctx)
		Expect(err).Should(Succeed())
		redisConn = strings.ReplaceAll(redisConn, "redis://", "")

		redisClient = goredis.NewClient(&goredis.Options{
			Addr:     redisConn,
			Password: redisTestPassword,
		})
		Expect(dbSize(ctx, redisClient)).Should(BeNumerically("==", 0))
	})

	When("the redis password is provided via a file", func() {
		It("authenticates to redis and shares cache", func(ctx context.Context) {
			// Create the secret file directly under /tmp so that the absolute path
			// is valid inside the container (which always has /tmp but may lack
			// user-specific subdirectories used by os.TempDir on this host).
			f, fErr := os.CreateTemp("/tmp", "blocky_e2e_secret-")
			Expect(fErr).Should(Succeed())
			_, fErr = f.WriteString(redisTestPassword)
			Expect(fErr).Should(Succeed())
			Expect(f.Close()).Should(Succeed())
			pwFile := f.Name()
			DeferCleanup(func() error { return os.Remove(pwFile) })

			blocky, err = createBlockyContainerWithFiles(ctx, e2eNet, []string{pwFile}, dedent(`
				log:
				  level: warn
				upstreams:
				  groups:
				    default:
				      - moka1
				redis:
				  address: redis:6379
				  required: true
				  password: file:`+pwFile+`
				`))
			Expect(err).Should(Succeed())

			By("resolving a query so blocky writes to redis", func() {
				msg := util.NewMsgWithQuestion("google.de.", A)
				Eventually(doDNSRequest, "5s", "2ms").WithArguments(ctx, blocky, msg).
					Should(BeDNSRecord("google.de.", A, "1.2.3.4"))
			})

			By("confirming blocky authenticated and populated the shared redis cache", func() {
				Eventually(dbSize, "5s", "10ms").WithArguments(ctx, redisClient).
					Should(BeNumerically(">", 0))
			})
		})
	})
})
