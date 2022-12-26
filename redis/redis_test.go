package redis

import (
	"encoding/json"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/util"
	"github.com/alicebob/miniredis/v2"
	"github.com/creasty/defaults"
	"github.com/google/uuid"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var (
	redisServer *miniredis.Miniredis
	redisClient *Client
	redisConfig *config.RedisConfig
	err         error
)

var _ = Describe("Redis client", func() {
	BeforeEach(func() {
		redisServer, err = miniredis.Run()

		Expect(err).Should(Succeed())

		DeferCleanup(redisServer.Close)

		var rcfg config.RedisConfig
		err = defaults.Set(&rcfg)

		Expect(err).Should(Succeed())

		rcfg.Address = redisServer.Addr()
		redisConfig = &rcfg
		redisClient, err = New(redisConfig)

		Expect(err).Should(Succeed())
		Expect(redisClient).ShouldNot(BeNil())
	})
	Describe("Client creation", func() {
		When("redis configuration has no address", func() {
			It("should return nil without error", func() {
				var rcfg config.RedisConfig
				err = defaults.Set(&rcfg)

				Expect(err).Should(Succeed())

				Expect(New(&rcfg)).Should(BeNil())
			})
		})
		When("redis configuration has invalid address", func() {
			It("should fail with error", func() {
				var rcfg config.RedisConfig
				err = defaults.Set(&rcfg)
				Expect(err).Should(Succeed())

				rcfg.Address = "127.0.0.1:0"

				_, err = New(&rcfg)

				Expect(err).Should(HaveOccurred())
			})
		})
		When("redis configuration has invalid password", func() {
			It("should fail with error", func() {
				var rcfg config.RedisConfig
				err = defaults.Set(&rcfg)
				Expect(err).Should(Succeed())

				rcfg.Address = redisServer.Addr()
				rcfg.Password = "wrong"

				_, err = New(&rcfg)

				Expect(err).Should(HaveOccurred())
			})
		})
	})

	Describe("Publish message", func() {
		When("Redis client publishes 'cache' message", func() {
			It("One new entry with TTL > 0 should be persisted in the database", func() {
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
						return redisServer.DB(redisConfig.Database).Exists(CacheStorePrefix + "example.com")
					}).Should(BeTrue())

					ttl := redisServer.DB(redisConfig.Database).TTL(CacheStorePrefix + "example.com")
					Expect(ttl.Seconds()).Should(BeNumerically("~", 123))
				})
			})

			It("One new entry with default TTL should be persisted in the database", func() {
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
						return redisServer.DB(redisConfig.Database).Exists(CacheStorePrefix + "example.com")
					}).Should(BeTrue())

					ttl := redisServer.DB(redisConfig.Database).TTL(CacheStorePrefix + "example.com")
					Expect(ttl.Seconds()).Should(BeNumerically("~", defaultCacheTime.Seconds()))
				})
			})
		})
		When("Redis client publishes 'enabled' message", func() {
			It("should propagate the message over redis", func() {
				redisClient.PublishEnabled(&EnabledMessage{
					State: true,
				})
				Eventually(func() map[string]int {
					return redisServer.PubSubNumSub(SyncChannelName)
				}).Should(HaveLen(1))
			})
		})
	})

	Describe("Receive message", func() {
		When("'enabled' message is received", func() {
			It("should propagate the message over the channel", func() {
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
			It("should propagate the message over the channel", func() {
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
			})
		})
		When("wrong data is received", func() {
			It("should not propagate the message over the channel if data is wrong", func() {
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
			})
			It("should not propagate the message over the channel if type is wrong", func() {
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

				Eventually(func() chan *EnabledMessage {
					return redisClient.EnabledChannel
				}).Should(HaveLen(lenE))

				Eventually(func() chan *CacheMessage {
					return redisClient.CacheChannel
				}).Should(HaveLen(lenC))
			})
		})
	})

	Describe("Read the redis cache and publish it to the channel", func() {
		When("GetRedisCache is called with valid database entries", func() {
			It("Should read data from Redis and propagate it via cache channel", func() {
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
					redisClient.GetRedisCache()

					Eventually(redisClient.CacheChannel).Should(HaveLen(1))
				})
			})
		})
		When("GetRedisCache is called and database contains not valid entry", func() {
			It("Should do nothing (only log error)", func() {
				Expect(redisServer.DB(redisConfig.Database).Set(CacheStorePrefix+"test", "test")).Should(Succeed())
				redisClient.GetRedisCache()
				Consistently(redisClient.CacheChannel).Should(BeEmpty())
			})
		})
	})
})
