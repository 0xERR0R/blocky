package e2e

import (
	"context"
	"net"
	"net/http"
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
				blocky1, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
					log:
					  level: warn
					upstreams:
					  groups:
					    default:
					      - moka1
					redis:
					  address: redis:6379
					`))
				Expect(err).Should(Succeed())

				blocky2, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
					log:
					  level: warn
					upstreams:
					  groups:
					    default:
					      - moka1
					redis:
					  address: redis:6379
					`))
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
				blocky1, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
					log:
					  level: warn
					upstreams:
					  groups:
					    default:
					      - moka1
					redis:
					  address: redis:6379
					`))
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
					blocky2, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
						log:
						  level: warn
						upstreams:
						  groups:
						    default:
						      - moka1
						redis:
						  address: redis:6379
						`))
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

	Describe("Blocking state sync via Redis", func() {
		When("Redis, blocking, and 2 blocky instances are configured", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createDNSMokkaContainer(ctx, "moka2", e2eNet,
					`A blocked.com/NOERROR("A 5.6.7.8 123")`,
				)
				Expect(err).Should(Succeed())

				_, err = createHTTPServerContainer(ctx, "httpserver", e2eNet, "list.txt", "blocked.com")
				Expect(err).Should(Succeed())

				blocky1, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
					log:
					  level: warn
					upstreams:
					  groups:
					    default:
					      - moka2
					ports:
					  http: 4000
					blocking:
					  denylists:
					    ads:
					      - http://httpserver:8080/list.txt
					  clientGroupsBlock:
					    default:
					      - ads
					redis:
					  address: redis:6379
					`))
				Expect(err).Should(Succeed())

				blocky2, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
					log:
					  level: warn
					upstreams:
					  groups:
					    default:
					      - moka2
					ports:
					  http: 4000
					blocking:
					  denylists:
					    ads:
					      - http://httpserver:8080/list.txt
					  clientGroupsBlock:
					    default:
					      - ads
					redis:
					  address: redis:6379
					`))
				Expect(err).Should(Succeed())
			})

			It("syncs blocking disable/enable between instances", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("blocked.com.", A)

				By("verifying blocking works on both instances", func() {
					Eventually(doDNSRequest, "5s", "2ms").WithArguments(ctx, blocky1, msg).
						Should(BeDNSRecord("blocked.com.", A, "0.0.0.0"))
					Eventually(doDNSRequest, "5s", "2ms").WithArguments(ctx, blocky2, msg).
						Should(BeDNSRecord("blocked.com.", A, "0.0.0.0"))
				})

				By("disabling blocking on instance1 via API", func() {
					host, port, err := getContainerHostPort(ctx, blocky1, "4000/tcp")
					Expect(err).Should(Succeed())

					resp, err := http.Get("http://" + net.JoinHostPort(host, port) + "/api/blocking/disable")
					Expect(err).Should(Succeed())
					defer resp.Body.Close()
					Expect(resp.StatusCode).Should(Equal(http.StatusOK))
				})

				By("verifying instance2 also has blocking disabled", func() {
					Eventually(doDNSRequest, "5s", "100ms").WithArguments(ctx, blocky2, msg).
						Should(BeDNSRecord("blocked.com.", A, "5.6.7.8"))
				})

				By("re-enabling blocking on instance1", func() {
					host, port, err := getContainerHostPort(ctx, blocky1, "4000/tcp")
					Expect(err).Should(Succeed())

					resp, err := http.Get("http://" + net.JoinHostPort(host, port) + "/api/blocking/enable")
					Expect(err).Should(Succeed())
					defer resp.Body.Close()
					Expect(resp.StatusCode).Should(Equal(http.StatusOK))
				})

				By("verifying instance2 re-enables blocking", func() {
					Eventually(doDNSRequest, "5s", "100ms").WithArguments(ctx, blocky2, msg).
						Should(BeDNSRecord("blocked.com.", A, "0.0.0.0"))
				})
			})
		})
	})

	Describe("Cache clear propagation via Redis", func() {
		When("Redis and 2 blocky instances share cached entries", func() {
			BeforeEach(func(ctx context.Context) {
				blocky1, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
					log:
					  level: warn
					upstreams:
					  groups:
					    default:
					      - moka1
					ports:
					  http: 4000
					caching:
					  minTime: 5m
					redis:
					  address: redis:6379
					`))
				Expect(err).Should(Succeed())
			})

			It("clears cache entries from Redis when flushed via API", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("google.de.", A)

				By("populating cache via instance1", func() {
					Eventually(doDNSRequest, "5s", "2ms").WithArguments(ctx, blocky1, msg).
						Should(BeDNSRecord("google.de.", A, "1.2.3.4"))
				})

				By("waiting for Redis to have the entry", func() {
					Eventually(dbSize, "5s", "2ms").WithArguments(ctx, redisClient).
						Should(BeNumerically(">=", 1))
				})

				By("flushing cache via instance1 API", func() {
					host, port, err := getContainerHostPort(ctx, blocky1, "4000/tcp")
					Expect(err).Should(Succeed())

					resp, err := http.Post(
						"http://"+net.JoinHostPort(host, port)+"/api/cache/flush",
						"application/json", nil)
					Expect(err).Should(Succeed())
					defer resp.Body.Close()
					Expect(resp.StatusCode).Should(Equal(http.StatusOK))
				})

				By("verifying Redis cache was cleared", func() {
					Eventually(dbSize, "5s", "100ms").WithArguments(ctx, redisClient).
						Should(BeNumerically("==", 0))
				})
			})
		})
	})

	Describe("Multiple query types via Redis cache", func() {
		When("both A and AAAA queries are cached", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createDNSMokkaContainer(ctx, "moka2", e2eNet,
					`A google/NOERROR("A 1.2.3.4 123")`,
					`AAAA google/NOERROR("AAAA 2001:db8::1 123")`,
				)
				Expect(err).Should(Succeed())

				blocky1, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
					log:
					  level: warn
					upstreams:
					  groups:
					    default:
					      - moka2
					redis:
					  address: redis:6379
					`))
				Expect(err).Should(Succeed())

				blocky2, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
					log:
					  level: warn
					upstreams:
					  groups:
					    default:
					      - moka2
					redis:
					  address: redis:6379
					`))
				Expect(err).Should(Succeed())
			})

			It("shares both A and AAAA cached responses via Redis", func(ctx context.Context) {
				By("querying A and AAAA on instance1", func() {
					Eventually(doDNSRequest, "5s", "2ms").
						WithArguments(ctx, blocky1, util.NewMsgWithQuestion("google.de.", A)).
						Should(BeDNSRecord("google.de.", A, "1.2.3.4"))

					Eventually(doDNSRequest, "5s", "2ms").
						WithArguments(ctx, blocky1, util.NewMsgWithQuestion("google.de.", AAAA)).
						Should(BeDNSRecord("google.de.", AAAA, "2001:db8::1"))
				})

				By("waiting for Redis entries", func() {
					Eventually(dbSize, "5s", "2ms").WithArguments(ctx, redisClient).
						Should(BeNumerically(">=", 2))
				})

				By("shutting down upstream", func() {
					Expect(mokka.Terminate(ctx)).Should(Succeed())
				})

				By("querying instance2 for both types from cache", func() {
					Eventually(doDNSRequest, "5s", "2ms").
						WithArguments(ctx, blocky2, util.NewMsgWithQuestion("google.de.", A)).
						Should(BeDNSRecord("google.de.", A, "1.2.3.4"))

					Eventually(doDNSRequest, "5s", "2ms").
						WithArguments(ctx, blocky2, util.NewMsgWithQuestion("google.de.", AAAA)).
						Should(BeDNSRecord("google.de.", AAAA, "2001:db8::1"))
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
