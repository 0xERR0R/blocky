package e2e

import (
	"context"
	"strings"

	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"
	"github.com/go-redis/redis/v8"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

var _ = Describe("Redis configuration tests", func() {
	var (
		e2eNet                  *testcontainers.DockerNetwork
		blocky1, blocky2, mokka testcontainers.Container
		redisClient             *redis.Client
		err                     error
	)

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)

		redisDB, err := createRedisContainer(ctx, e2eNet)
		Expect(err).Should(Succeed())

		redisConnectionString, err := redisDB.ConnectionString(ctx)
		Expect(err).Should(Succeed())

		redisConnectionString = strings.ReplaceAll(redisConnectionString, "redis://", "")

		redisClient = redis.NewClient(&redis.Options{
			Addr: redisConnectionString,
		})

		Expect(dbSize(ctx, redisClient)).Should(BeNumerically("==", 0))

		mokka, err = createDNSMokkaContainer(ctx, "moka1", e2eNet, `A google/NOERROR("A 1.2.3.4 123")`)
		Expect(err).Should(Succeed())
	})

	Describe("Cache sharing between blocky instances", func() {
		When("Redis and 2 blocky instances are configured", func() {
			BeforeEach(func(ctx context.Context) {
				blocky1, err = createBlockyContainer(ctx, e2eNet,
					"log:",
					"  level: warn",
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka1",
					"redis:",
					"  address: redis:6379",
				)
				Expect(err).Should(Succeed())

				blocky2, err = createBlockyContainer(ctx, e2eNet,
					"log:",
					"  level: warn",
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka1",
					"redis:",
					"  address: redis:6379",
				)
				Expect(err).Should(Succeed())
			})
			It("2nd instance of blocky should use cache from redis", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("google.de.", A)
				By("Query first blocky instance, should store cache in redis", func() {
					Eventually(doDNSRequest, "5s", "2ms").WithArguments(ctx, blocky1, msg).
						Should(
							SatisfyAll(
								BeDNSRecord("google.de.", A, "1.2.3.4"),
								HaveTTL(BeNumerically("==", 123)),
							))
				})

				By("Check redis, must contain one cache entry", func() {
					Eventually(dbSize, "5s", "2ms").WithArguments(ctx, redisClient).Should(BeNumerically("==", 1))
				})

				By("Shutdown the upstream DNS server", func() {
					Expect(mokka.Terminate(ctx)).Should(Succeed())
				})

				By("Query second blocky instance, should use cache from redis", func() {
					Eventually(doDNSRequest, "5s", "2ms").WithArguments(ctx, blocky2, msg).
						Should(
							SatisfyAll(
								BeDNSRecord("google.de.", A, "1.2.3.4"),
								HaveTTL(BeNumerically("<=", 123)),
							))
				})

				By("No warnings/errors in log", func() {
					Expect(getContainerLogs(ctx, blocky1)).Should(BeEmpty())
					Expect(getContainerLogs(ctx, blocky2)).Should(BeEmpty())
				})
			})
		})
	})

	Describe("Cache loading on startup", func() {
		When("Redis and 1 blocky instance are configured", func() {
			BeforeEach(func(ctx context.Context) {
				blocky1, err = createBlockyContainer(ctx, e2eNet,
					"log:",
					"  level: warn",
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka1",
					"redis:",
					"  address: redis:6379",
				)
				Expect(err).Should(Succeed())
			})
			It("should load cache from redis after start", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("google.de.", A)
				By("Query first blocky instance, should store cache in redis\"", func() {
					Eventually(doDNSRequest, "5s", "2ms").WithArguments(ctx, blocky1, msg).
						Should(
							SatisfyAll(
								BeDNSRecord("google.de.", A, "1.2.3.4"),
								HaveTTL(BeNumerically("==", 123)),
							))
				})

				By("Check redis, must contain one cache entry", func() {
					Eventually(dbSize).WithArguments(ctx, redisClient).Should(BeNumerically("==", 1))
				})

				By("start other instance of blocky now -> it should load the cache from redis", func() {
					blocky2, err = createBlockyContainer(ctx, e2eNet,
						"log:",
						"  level: warn",
						"upstreams:",
						"  groups:",
						"    default:",
						"      - moka1",
						"redis:",
						"  address: redis:6379",
					)
					Expect(err).Should(Succeed())
				})

				By("Shutdown the upstream DNS server", func() {
					Expect(mokka.Terminate(ctx)).Should(Succeed())
				})

				By("Query second blocky instance", func() {
					Eventually(doDNSRequest, "5s", "2ms").WithArguments(ctx, blocky2, msg).
						Should(
							SatisfyAll(
								BeDNSRecord("google.de.", A, "1.2.3.4"),
								HaveTTL(BeNumerically("<=", 123)),
							))
				})

				By("No warnings/errors in log", func() {
					Expect(getContainerLogs(ctx, blocky1)).Should(BeEmpty())
					Expect(getContainerLogs(ctx, blocky2)).Should(BeEmpty())
				})
			})
		})
	})
})

func dbSize(ctx context.Context, redisClient *redis.Client) (int64, error) {
	return redisClient.DBSize(ctx).Result()
}
