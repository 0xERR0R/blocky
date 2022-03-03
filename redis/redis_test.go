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

var _ = BeforeSuite(func() {
	redisServer, err = miniredis.Run()

	Expect(err).Should(Succeed())

	var rcfg config.RedisConfig
	err = defaults.Set(&rcfg)

	Expect(err).Should(Succeed())

	rcfg.Address = redisServer.Addr()
	redisConfig = &rcfg
	redisClient, err = New(redisConfig)

	Expect(err).Should(Succeed())
	Expect(redisClient).ShouldNot(BeNil())
})

var _ = AfterSuite(func() {
	redisServer.Close()
})

var _ = Describe("Redis client", func() {
	When("created", func() {
		It("with no address", func() {
			var rcfg config.RedisConfig
			err = defaults.Set(&rcfg)

			Expect(err).Should(Succeed())

			var rClient *Client

			rClient, err = New(&rcfg)

			Expect(err).Should(Succeed())
			Expect(rClient).Should(BeNil())
		})
		It("with invalid address", func() {
			var rcfg config.RedisConfig
			err = defaults.Set(&rcfg)
			Expect(err).Should(Succeed())

			rcfg.Address = "test:123"

			_, err = New(&rcfg)

			Expect(err).ShouldNot(Succeed())
		})
		It("with invalid password", func() {
			var rcfg config.RedisConfig
			err = defaults.Set(&rcfg)
			Expect(err).Should(Succeed())

			rcfg.Address = redisServer.Addr()
			rcfg.Password = "wrong"

			_, err = New(&rcfg)

			Expect(err).ShouldNot(Succeed())
		})
	})
	When("publish", func() {
		It("cache works", func() {
			var res *dns.Msg

			res, err = util.NewMsgWithAnswer("example.com.", 123, dns.TypeA, "123.124.122.123")

			Expect(err).Should(Succeed())

			redisClient.PublishCache("example.com", res)
			Eventually(func() []string {
				return redisServer.DB(redisConfig.Database).Keys()
			}, "100ms").Should(HaveLen(1))
		})
		It("enabled works", func() {
			redisClient.PublishEnabled(&EnabledMessage{
				State: true,
			})
			Eventually(func() map[string]int {
				return redisServer.PubSubNumSub(SyncChannelName)
			}, "50ms").Should(HaveLen(1))
		})
	})
	When("received", func() {
		It("enabled", func() {
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
			}, "100ms").Should(HaveLen(lenE + 1))
		})
		It("doesn't work", func() {
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
			}, "100ms").Should(HaveLen(lenE))

			Eventually(func() chan *CacheMessage {
				return redisClient.CacheChannel
			}, "100ms").Should(HaveLen(lenC))
		})
	})
	When("GetRedisCache", func() {
		It("works", func() {
			var res *dns.Msg

			origCount := len(redisClient.CacheChannel)
			res, err = util.NewMsgWithAnswer("example.com.", 123, dns.TypeA, "123.124.122.123")

			Expect(err).Should(Succeed())

			redisClient.PublishCache("example.com", res)

			Eventually(func() []string {
				return redisServer.DB(redisConfig.Database).Keys()
			}, "100ms").Should(HaveLen(1))

			redisClient.GetRedisCache()

			Eventually(func() []string {
				return redisServer.DB(redisConfig.Database).Keys()
			}, "100ms").Should(HaveLen(origCount + 1))

		})
	})
})
