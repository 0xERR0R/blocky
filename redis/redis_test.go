package redis

import (
	"context"
	"encoding/json"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/util"
	"github.com/alicebob/miniredis/v2"
	"github.com/creasty/defaults"
	"github.com/google/uuid"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	exampleComKey = CacheStorePrefix + "example.com"
)

var _ = Describe("Redis client", func() {
	var (
		redisConfig *config.Redis

		redisClient *Client

		err error
	)

	BeforeEach(func() {
		var rcfg config.Redis
		Expect(defaults.Set(&rcfg)).Should(Succeed())
		redisConfig = &rcfg
	})

	Describe("Client creation", func() {
		When("redis configuration has no address", func() {
			It("should return nil without error", func(ctx context.Context) {
				Expect(New(ctx, redisConfig)).Should(BeNil())
			})
		})

		When("redis configuration has invalid address", func() {
			BeforeEach(func() {
				redisConfig.Address = "127.0.0.1:0"
			})

			It("should fail with error", func(ctx context.Context) {
				_, err = New(ctx, redisConfig)
				Expect(err).Should(HaveOccurred())
			})
		})

		When("sentinel is enabled without servers", func() {
			BeforeEach(func() {
				redisConfig.Address = "test"
				redisConfig.SentinelAddresses = []string{"127.0.0.1:0"}
			})

			It("should fail with error", func(ctx context.Context) {
				_, err = New(ctx, redisConfig)
				Expect(err).Should(HaveOccurred())
			})
		})

		When("redis configuration has invalid password", func() {
			BeforeEach(func() {
				setupRedisServer(redisConfig)
				redisConfig.Password = "wrong"
			})

			It("should fail with error", func(ctx context.Context) {
				_, err = New(ctx, redisConfig)
				Expect(err).Should(HaveOccurred())
			})
		})
	})

	Describe("Publish message", func() {
		var redisServer *miniredis.Miniredis
		BeforeEach(func() {
			redisServer = setupRedisServer(redisConfig)
		})

		When("Redis client publishes 'cache' message", func() {
			It("One new entry with TTL > 0 should be persisted in the database", func(ctx context.Context) {
				redisClient, err = New(ctx, redisConfig)
				Expect(err).Should(Succeed())

				By("Database is empty", func() {
					Eventually(func() []string {
						return redisServer.DB(redisConfig.Database).Keys()
					}).Should(BeEmpty())
				})

				By("publish new message with TTL > 0", func() {
					res, err := util.NewMsgWithAnswer("example.com.", 123, dns.Type(dns.TypeA), "123.124.122.123")

					Expect(err).Should(Succeed())

					redisClient.PublishCache("example.com", res)
				})

				By("Database has one entry with correct TTL", func() {
					Eventually(func() bool {
						return redisServer.DB(redisConfig.Database).Exists(exampleComKey)
					}).Should(BeTrue())

					ttl := redisServer.DB(redisConfig.Database).TTL(exampleComKey)
					Expect(ttl.Seconds()).Should(BeNumerically("~", 123))
				})
			})

			It("One new entry with default TTL should be persisted in the database", func(ctx context.Context) {
				redisClient, err = New(ctx, redisConfig)
				Expect(err).Should(Succeed())

				By("Database is empty", func() {
					Eventually(func() []string {
						return redisServer.DB(redisConfig.Database).Keys()
					}).Should(BeEmpty())
				})

				By("publish new message with TTL = 0", func() {
					res, err := util.NewMsgWithAnswer("example.com.", 0, dns.Type(dns.TypeA), "123.124.122.123")

					Expect(err).Should(Succeed())

					redisClient.PublishCache("example.com", res)
				})

				By("Database has one entry with default TTL", func() {
					Eventually(func() bool {
						return redisServer.DB(redisConfig.Database).Exists(exampleComKey)
					}).Should(BeTrue())

					ttl := redisServer.DB(redisConfig.Database).TTL(exampleComKey)
					Expect(ttl.Seconds()).Should(BeNumerically("~", defaultCacheTime.Seconds()))
				})
			})
		})
		When("Redis client publishes 'enabled' message", func() {
			It("should propagate the message over redis", func(ctx context.Context) {
				redisClient, err = New(ctx, redisConfig)
				Expect(err).Should(Succeed())

				redisClient.PublishEnabled(ctx, &EnabledMessage{
					State: true,
				})
				Eventually(func() map[string]int {
					return redisServer.PubSubNumSub(SyncChannelName)
				}).Should(HaveLen(1))
			}, SpecTimeout(time.Second*6))
		})
	})

	Describe("Receive message", func() {
		var redisServer *miniredis.Miniredis
		BeforeEach(func() {
			redisServer = setupRedisServer(redisConfig)
		})
		When("'enabled' message is received", func() {
			It("should propagate the message over the channel", func(ctx context.Context) {
				redisClient, err = New(ctx, redisConfig)
				Expect(err).Should(Succeed())

				var binState []byte
				binState, err = json.Marshal(EnabledMessage{State: true})
				Expect(err).Should(Succeed())

				var id []byte
				id, err = uuid.New().MarshalBinary()
				Expect(err).Should(Succeed())

				var binMsg []byte
				binMsg, err = json.Marshal(redisMessage{
					Type:    messageTypeEnable,
					Message: binState,
					Client:  id,
				})
				Expect(err).Should(Succeed())

				lenE := len(redisClient.EnabledChannel)

				rec := redisServer.Publish(SyncChannelName, string(binMsg))
				Expect(rec).Should(Equal(1))

				Eventually(func() chan *EnabledMessage {
					return redisClient.EnabledChannel
				}).Should(HaveLen(lenE + 1))
			})
		})
		When("'cache' message is received", func() {
			It("should propagate the message over the channel", func(ctx context.Context) {
				redisClient, err = New(ctx, redisConfig)
				Expect(err).Should(Succeed())

				res, err := util.NewMsgWithAnswer("example.com.", 123, dns.Type(dns.TypeA), "123.124.122.123")

				Expect(err).Should(Succeed())

				var binState []byte
				binState, err = res.Pack()
				Expect(err).Should(Succeed())

				var id []byte
				id, err = uuid.New().MarshalBinary()
				Expect(err).Should(Succeed())

				var binMsg []byte
				binMsg, err = json.Marshal(redisMessage{
					Key:     "example.com",
					Type:    messageTypeCache,
					Message: binState,
					Client:  id,
				})
				Expect(err).Should(Succeed())

				lenE := len(redisClient.CacheChannel)

				rec := redisServer.Publish(SyncChannelName, string(binMsg))
				Expect(rec).Should(Equal(1))

				Eventually(func() chan *CacheMessage {
					return redisClient.CacheChannel
				}).Should(HaveLen(lenE + 1))
			}, SpecTimeout(time.Second*6))
		})
		When("wrong data is received", func() {
			It("should not propagate the message over the channel if data is wrong", func(ctx context.Context) {
				redisClient, err = New(ctx, redisConfig)
				Expect(err).Should(Succeed())

				var id []byte
				id, err = uuid.New().MarshalBinary()
				Expect(err).Should(Succeed())

				var binMsg []byte
				binMsg, err = json.Marshal(redisMessage{
					Key:     "unknown",
					Type:    messageTypeCache,
					Message: []byte("test"),
					Client:  id,
				})
				Expect(err).Should(Succeed())

				lenE := len(redisClient.EnabledChannel)
				lenC := len(redisClient.CacheChannel)

				rec := redisServer.Publish(SyncChannelName, string(binMsg))
				Expect(rec).Should(Equal(1))

				Eventually(func() chan *EnabledMessage {
					return redisClient.EnabledChannel
				}).Should(HaveLen(lenE))

				Eventually(func() chan *CacheMessage {
					return redisClient.CacheChannel
				}).Should(HaveLen(lenC))
			}, SpecTimeout(time.Second*6))
			It("should not propagate the message over the channel if type is wrong", func(ctx context.Context) {
				redisClient, err = New(ctx, redisConfig)
				Expect(err).Should(Succeed())

				var id []byte
				id, err = uuid.New().MarshalBinary()
				Expect(err).Should(Succeed())

				var binMsg []byte
				binMsg, err = json.Marshal(redisMessage{
					Key:     "unknown",
					Type:    99,
					Message: []byte("test"),
					Client:  id,
				})
				Expect(err).Should(Succeed())

				lenE := len(redisClient.EnabledChannel)
				lenC := len(redisClient.CacheChannel)

				rec := redisServer.Publish(SyncChannelName, string(binMsg))
				Expect(rec).Should(Equal(1))

				time.Sleep(2 * time.Second)

				Eventually(func() chan *EnabledMessage {
					return redisClient.EnabledChannel
				}).Should(HaveLen(lenE))

				Eventually(func() chan *CacheMessage {
					return redisClient.CacheChannel
				}).Should(HaveLen(lenC))
			}, SpecTimeout(time.Second*6))
		})
	})

	Describe("Read the redis cache and publish it to the channel", func() {
		var redisServer *miniredis.Miniredis
		BeforeEach(func() {
			redisServer = setupRedisServer(redisConfig)
		})
		When("GetRedisCache is called with valid database entries", func() {
			It("Should read data from Redis and propagate it via cache channel", func(ctx context.Context) {
				redisClient, err = New(ctx, redisConfig)
				Expect(err).Should(Succeed())

				By("Database is empty", func() {
					Eventually(func() []string {
						return redisServer.DB(redisConfig.Database).Keys()
					}).Should(BeEmpty())
				})

				By("Put valid data in Redis by publishing the cache entry", func() {
					var res *dns.Msg

					res, err = util.NewMsgWithAnswer("example.com.", 123, dns.Type(dns.TypeA), "123.124.122.123")

					Expect(err).Should(Succeed())

					redisClient.PublishCache("example.com", res)
				})

				By("Database has one entry now", func() {
					Eventually(func() []string {
						return redisServer.DB(redisConfig.Database).Keys()
					}).Should(HaveLen(1))
				})

				By("call GetRedisCache - It should read one entry from redis and propagate it via channel", func() {
					redisClient.GetRedisCache(ctx)

					Eventually(redisClient.CacheChannel).Should(HaveLen(1))
				})
			}, SpecTimeout(time.Second*4))
		})
		When("GetRedisCache is called and database contains not valid entry", func() {
			It("Should do nothing (only log error)", func(ctx context.Context) {
				redisClient, err = New(ctx, redisConfig)
				Expect(err).Should(Succeed())

				Expect(redisServer.DB(redisConfig.Database).Set(CacheStorePrefix+"test", "test")).Should(Succeed())
				redisClient.GetRedisCache(ctx)
				Consistently(redisClient.CacheChannel).Should(BeEmpty())
			}, SpecTimeout(time.Second*2))
		})
	})
})

func setupRedisServer(cfg *config.Redis) *miniredis.Miniredis {
	redisServer, err := miniredis.Run()
	Expect(err).Should(Succeed())
	DeferCleanup(redisServer.Close)
	cfg.Address = redisServer.Addr()

	return redisServer
}
