package redis

import (
	"context"

	"github.com/0xERR0R/blocky/config"
	"github.com/alicebob/miniredis/v2"
	"github.com/creasty/defaults"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Redis connection factory", func() {
	var redisConfig *config.Redis

	BeforeEach(func() {
		var rcfg config.Redis
		Expect(defaults.Set(&rcfg)).Should(Succeed())
		redisConfig = &rcfg
	})

	When("configuration has no address", func() {
		It("should return nil without error", func(ctx context.Context) {
			client, err := New(ctx, redisConfig)
			Expect(err).Should(Succeed())
			Expect(client).Should(BeNil())
		})
	})

	When("configuration has invalid address", func() {
		BeforeEach(func() {
			redisConfig.Address = "127.0.0.1:0"
		})

		It("should fail with error", func(ctx context.Context) {
			_, err := New(ctx, redisConfig)
			Expect(err).Should(HaveOccurred())
		})
	})

	When("sentinel is enabled without servers", func() {
		BeforeEach(func() {
			redisConfig.Address = "test"
			redisConfig.SentinelAddresses = []string{"127.0.0.1:0"}
		})

		It("should fail with error", func(ctx context.Context) {
			_, err := New(ctx, redisConfig)
			Expect(err).Should(HaveOccurred())
		})
	})

	When("configuration has valid address", func() {
		BeforeEach(func() {
			redisServer, err := miniredis.Run()
			Expect(err).Should(Succeed())
			DeferCleanup(redisServer.Close)
			redisConfig.Address = redisServer.Addr()
		})

		It("should return a connected client", func(ctx context.Context) {
			client, err := New(ctx, redisConfig)
			Expect(err).Should(Succeed())
			Expect(client).ShouldNot(BeNil())
		})
	})

	When("configuration has invalid password", func() {
		BeforeEach(func() {
			redisServer, err := miniredis.Run()
			Expect(err).Should(Succeed())
			DeferCleanup(redisServer.Close)
			redisServer.RequireAuth("correct-password")
			redisConfig.Address = redisServer.Addr()
			redisConfig.Password = "wrong"
		})

		It("should fail with error", func(ctx context.Context) {
			_, err := New(ctx, redisConfig)
			Expect(err).Should(HaveOccurred())
		})
	})
})
