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

var _ = Describe("Redis", func() {

	var (
		redisServer *miniredis.Miniredis
		redisClient *Client
		err         error
	)

	BeforeSuite(func() {
		redisServer, err = miniredis.Run()

		Expect(err).Should(Succeed())
		var rCfg config.RedisConfig

		err = defaults.Set(&rCfg)

		Expect(err).Should(Succeed())

		rCfg.Address = redisServer.Addr()

		redisClient, err = New(&rCfg)

		Expect(err).Should(Succeed())
		Expect(redisClient).ShouldNot(BeNil())
	})
	AfterSuite(func() {
		redisServer.Close()
	})

	When("Client", func() {
		It("Publish", func() {
			var res *dns.Msg

			res, err = util.NewMsgWithAnswer("example.com.", 123, dns.TypeA, "123.124.122.123")

			Expect(err).Should(Succeed())

			redisClient.PublishCache("example.com.", &model.Response{
				Res:    res,
				RType:  model.ResponseTypeCACHED,
				Reason: "CACHED",
			})
		})
	})
})
