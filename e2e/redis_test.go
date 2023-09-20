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

	BeforeEach(func() {
		redisDB, err = createRedisContainer()

		Expect(err).Should(Succeed())
		DeferCleanup(redisDB.Terminate)

		redisConnectionString, err := redisDB.ConnectionString(context.Background())
		Expect(err).Should(Succeed())

		redisConnectionString = strings.ReplaceAll(redisConnectionString, "redis://", "")

		redisClient = redis.NewClient(&redis.Options{
			Addr: redisConnectionString,
		})

		Expect(dbSize(redisClient)).Should(BeNumerically("==", 0))

		moka, err = createDNSMokkaContainer("moka1", `A google/NOERROR("A 1.2.3.4 123")`)

		Expect(err).Should(Succeed())
		DeferCleanup(func() {
			_ = moka.Terminate(context.Background())
		})
	})

	Describe("Cache sharing between blocky instances", func() {
		When("Redis and 2 blocky instances are configured", func() {
			BeforeEach(func() {
				blocky1, err = createBlockyContainer(tmpDir,
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

				blocky2, err = createBlockyContainer(tmpDir,
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
			It("2nd instance of blocky should use cache from redis", func() {
				msg := util.NewMsgWithQuestion("google.de.", A)
				By("Query first blocky instance, should store cache in redis", func() {
					Eventually(doDNSRequest, "5s", "2ms").WithArguments(blocky1, msg).
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
					Expect(moka.Terminate(context.Background())).Should(Succeed())
				})

				By("Query second blocky instance, should use cache from redis", func() {
					Eventually(doDNSRequest, "5s", "2ms").WithArguments(blocky2, msg).
						Should(
							SatisfyAll(
								BeDNSRecord("google.de.", A, "1.2.3.4"),
								HaveTTL(BeNumerically("<=", 123)),
							))
				})

				By("No warnings/errors in log", func() {
					Expect(getContainerLogs(blocky1)).Should(BeEmpty())
					Expect(getContainerLogs(blocky2)).Should(BeEmpty())
				})
			})
		})
	})

	Describe("Cache loading on startup", func() {
		When("Redis and 1 blocky instance are configured", func() {
			BeforeEach(func() {
				blocky1, err = createBlockyContainer(tmpDir,
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
			It("should load cache from redis after start", func() {
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
					blocky2, err = createBlockyContainer(tmpDir,
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
					Expect(moka.Terminate(context.Background())).Should(Succeed())
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
					Expect(getContainerLogs(blocky1)).Should(BeEmpty())
					Expect(getContainerLogs(blocky2)).Should(BeEmpty())
				})
			})
		})
	})
})

func dbSize(redisClient *redis.Client) (int64, error) {
	return redisClient.DBSize(context.Background()).Result()
}
