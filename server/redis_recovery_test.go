package server

import (
	"context"
	"encoding/json"
	"net"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/evt"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/redis"
	"github.com/0xERR0R/blocky/resolver"
	"github.com/0xERR0R/blocky/util"
	"github.com/alicebob/miniredis/v2"
	miniserver "github.com/alicebob/miniredis/v2/server"
	"github.com/creasty/defaults"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Optional Redis recovery", func() {
	var cfg config.Config

	BeforeEach(func() {
		cfg = config.Config{}
		Expect(defaults.Set(&cfg)).Should(Succeed())
		cfg.Ports.DNS = config.ListenConfig{}
		cfg.Upstreams.Groups = map[string][]config.Upstream{
			"default": {{Net: config.NetProtocolTcpUdp, Host: "127.0.0.1", Port: 53}},
		}
		cfg.Redis.ConnectionAttempts = 1
		cfg.Redis.ConnectionCooldown = config.Duration(10 * time.Millisecond)
	})

	It("resumes cache writes and blocking synchronization after Redis starts", func(ctx context.Context) {
		redisServer, err := miniredis.Run()
		Expect(err).Should(Succeed())
		DeferCleanup(redisServer.Close)
		address := redisServer.Addr()
		redisServer.Close()

		upstream := resolver.NewMockUDPUpstreamServer().WithAnswerFn(func(request *dns.Msg) *dns.Msg {
			answer, err := util.NewMsgWithAnswer(util.ExtractDomain(request.Question[0]), 300, dns.Type(dns.TypeA), "203.0.113.77")
			Expect(err).Should(Succeed())

			return answer
		})
		upstreamConfig := upstream.Start()
		DeferCleanup(upstream.Close)
		cfg.Upstreams.Groups = map[string][]config.Upstream{"default": {upstreamConfig}}
		cfg.Redis.Address = address

		srv, err := NewServer(ctx, &cfg)
		Expect(err).Should(Succeed())
		DeferCleanup(func() { Expect(srv.Stop(ctx)).Should(Succeed()) })
		query := func(domain string) {
			response, err := srv.queryResolver.Resolve(ctx, &model.Request{
				Req:      util.NewMsgWithQuestion(domain, dns.Type(dns.TypeA)),
				Protocol: model.RequestProtocolUDP,
			})
			Expect(err).Should(Succeed())
			Expect(response.Res.Answer).Should(HaveLen(1))
			Expect(response.Res.Answer[0].(*dns.A).A.Equal(net.ParseIP("203.0.113.77"))).Should(BeTrue())
		}
		query("cache-unavailable.example.com.")
		Expect(redisServer.StartAddr(address)).Should(Succeed())
		query("cache-recovered.example.com.")
		key := "blocky:cache:" + util.GenerateCacheKey(dns.Type(dns.TypeA), "cache-recovered.example.com")
		Eventually(func(g Gomega) {
			packed, err := redisServer.Get(key)
			g.Expect(err).Should(Succeed())
			response := new(dns.Msg)
			g.Expect(response.Unpack([]byte(packed))).Should(Succeed())
			g.Expect(response.Question[0].Name).Should(Equal("cache-recovered.example.com."))
			g.Expect(response.Answer[0].(*dns.A).A.Equal(net.ParseIP("203.0.113.77"))).Should(BeTrue())
		}).WithTimeout(5 * time.Second).Should(Succeed())

		received := make(chan evt.BlockingState, 1)
		handler := func(state evt.BlockingState) {
			select {
			case received <- state:
			default:
			}
		}
		Expect(evt.Bus().Subscribe(evt.BlockingStateChangedRemote, handler)).Should(Succeed())
		DeferCleanup(func() { Expect(evt.Bus().Unsubscribe(evt.BlockingStateChangedRemote, handler)).Should(Succeed()) })
		expected := evt.BlockingState{Enabled: true, Groups: []string{"recovery"}}
		payload, err := json.Marshal(map[string]any{"s": expected, "c": "recovery-test"})
		Expect(err).Should(Succeed())
		Eventually(func() int { return redisServer.Publish(redis.EventBridgeChannel, string(payload)) }).
			WithTimeout(5 * time.Second).Should(BeNumerically(">", 0))
		Eventually(received).Should(Receive(Equal(expected)))
	}, SpecTimeout(15*time.Second))

	It("does not repeat blocking checks after the optional startup check fails", func(specCtx context.Context) {
		redisServer, err := miniredis.Run()
		Expect(err).Should(Succeed())
		DeferCleanup(redisServer.Close)
		ctx, cancel := context.WithCancel(specCtx)
		DeferCleanup(cancel)
		redisServer.Server().SetPreHook(func(peer *miniserver.Peer, command string, _ ...string) bool {
			if command == "PING" {
				peer.WriteError("ERR unavailable")
			} else {
				<-ctx.Done()
			}

			return true
		})
		cfg.Redis.Address = redisServer.Addr()
		srv, err := NewServer(ctx, &cfg)
		Expect(err).Should(Succeed())
		DeferCleanup(func() { Expect(srv.Stop(ctx)).Should(Succeed()) })
	}, SpecTimeout(2*time.Second))

	It("closes the client when a required startup Ping fails", func(ctx context.Context) {
		redisServer, err := miniredis.Run()
		Expect(err).Should(Succeed())
		DeferCleanup(redisServer.Close)
		redisServer.Server().SetPreHook(func(peer *miniserver.Peer, command string, _ ...string) bool {
			if command != "PING" {
				return false
			}
			peer.WriteError("ERR unavailable")

			return true
		})
		cfg.Redis.Address = redisServer.Addr()
		cfg.Redis.Required = true

		srv, err := NewServer(ctx, &cfg)
		Expect(srv).Should(BeNil())
		Expect(err).Should(MatchError(ContainSubstring("failed to create required Redis client")))
		Eventually(redisServer.CurrentConnectionCount).Should(BeZero())
	}, SpecTimeout(3*time.Second))

	It("closes the client when a required subscription fails after Ping succeeds", func(ctx context.Context) {
		redisServer, err := miniredis.Run()
		Expect(err).Should(Succeed())
		DeferCleanup(redisServer.Close)
		redisServer.Server().SetPreHook(func(peer *miniserver.Peer, command string, _ ...string) bool {
			if command != "SUBSCRIBE" {
				return false
			}
			peer.WriteError("NOPERM subscription denied")

			return true
		})
		cfg.Redis.Address = redisServer.Addr()
		cfg.Redis.Required = true
		srv, err := NewServer(ctx, &cfg)
		Expect(srv).Should(BeNil())
		Expect(err).Should(MatchError(ContainSubstring("failed to create required Redis event bridge")))
		Eventually(redisServer.CurrentConnectionCount).Should(BeZero())
	}, SpecTimeout(3*time.Second))
})
