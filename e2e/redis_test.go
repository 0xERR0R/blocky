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
	redisTc "github.com/testcontainers/testcontainers-go/modules/redis"
)

var _ = Describe("Redis configuration tests", func() {
	var blocky1, blocky2, moka testcontainers.Container
	var redisDB *redisTc.RedisContainer
	var redisClient *redis.Client
	var err error

	BeforeEach(func(ctx context.Context) {
		redisDB, err = createRedisContainer(ctx)

		Expect(err).Should(Succeed())
		DeferCleanup(redisDB.Terminate)

		redisConnectionString, err := redisDB.ConnectionString(ctx)
		Expect(err).Should(Succeed())

		redisConnectionString = strings.ReplaceAll(redisConnectionString, "redis://", "")

		redisClient = redis.NewClient(&redis.Options{
			Addr: redisConnectionString,
		})

		Expect(dbSize(ctx, redisClient)).Should(BeNumerically("==", 0))

		moka, err = createDNSMokkaContainer(ctx, "moka1", `A google/NOERROR("A 1.2.3.4 123")`)

		Expect(err).Should(Succeed())
		DeferCleanup(func(ctx context.Context) {
			_ = moka.Terminate(ctx)
		})
	})

	Describe("Cache sharing between blocky instances", func() {
		When("Redis and 2 blocky instances are configured", func() {
			BeforeEach(func(ctx context.Context) {
				blocky1, err = createBlockyContainer(ctx, tmpDir,
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
				DeferCleanup(blocky1.Terminate)

				blocky2, err = createBlockyContainer(ctx, tmpDir,
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
				DeferCleanup(blocky2.Terminate)
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
					Eventually(dbSize, "5s", "2ms").WithArguments(redisClient).Should(BeNumerically("==", 1))
				})

				By("Shutdown the upstream DNS server", func() {
					Expect(moka.Terminate(ctx)).Should(Succeed())
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
				blocky1, err = createBlockyContainer(ctx, tmpDir,
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
				DeferCleanup(blocky1.Terminate)
			})
			It("should load cache from redis after start", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("google.de.", A)
				By("Query first blocky instance, should store cache in redis\"", func() {
					Eventually(doDNSRequest, "5s", "2ms").WithArguments(blocky1, msg).
						Should(
							SatisfyAll(
								BeDNSRecord("google.de.", A, "1.2.3.4"),
								HaveTTL(BeNumerically("==", 123)),
							))
				})

				By("Check redis, must contain one cache entry", func() {
					Eventually(dbSize).WithArguments(redisClient).Should(BeNumerically("==", 1))
				})

				By("start other instance of blocky now -> it should load the cache from redis", func() {
					blocky2, err = createBlockyContainer(ctx, tmpDir,
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
					DeferCleanup(blocky2.Terminate)
				})

				By("Shutdown the upstream DNS server", func() {
					Expect(moka.Terminate(ctx)).Should(Succeed())
				})

				By("Query second blocky instance", func() {
					Eventually(doDNSRequest, "5s", "2ms").WithArguments(blocky2, msg).
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
