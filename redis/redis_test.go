package redis

import (
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/alicebob/miniredis/v2"
	"github.com/creasty/defaults"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Redis client", func() {

	var (
		redisServer *miniredis.Miniredis
		redisClient *Client
		redisConfig *config.RedisConfig
		err         error
	)

	BeforeSuite(func() {
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
	AfterSuite(func() {
		redisServer.Close()
	})
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
		It("works", func() {
			var res *dns.Msg

			res, err = util.NewMsgWithAnswer("example.com.", 123, dns.TypeA, "123.124.122.123")

			Expect(err).Should(Succeed())

			redisClient.PublishCache("example.com.", &model.Response{
				Res:    res,
				RType:  model.ResponseTypeCACHED,
				Reason: "CACHED",
			})

			keysLen := len(redisServer.DB(redisConfig.Database).Keys())
			Expect(keysLen).To(Equal(1))
		})
	})
})
