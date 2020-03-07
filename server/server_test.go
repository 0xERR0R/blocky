package server

import (
	"blocky/config"
	"blocky/resolver"
	"blocky/util"
	"fmt"
	"log"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

var mockClientName string

// test case definition
var tests = []struct {
	name           string
	request        *dns.Msg
	mockClientName string
	respValidator  func(*testing.T, *dns.Msg)
}{
	{
		// resolve query via external dns
		name:    "resolveWithUpstream",
		request: util.NewMsgWithQuestion("google.de.", dns.TypeA),
		respValidator: func(t *testing.T, resp *dns.Msg) {
			assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
			assert.Equal(t, "google.de.\t123\tIN\tA\t123.124.122.122", resp.Answer[0].String())
		},
	},
	{
		// custom dnd entry with exact match
		name:    "customDns",
		request: util.NewMsgWithQuestion("custom.lan.", dns.TypeA),
		respValidator: func(t *testing.T, resp *dns.Msg) {
			assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
			assert.Equal(t, "custom.lan.\t3600\tIN\tA\t192.168.178.55", resp.Answer[0].String())
		},
	},
	{
		// sub domain custom dns
		name:    "customDnsWithSubdomain",
		request: util.NewMsgWithQuestion("host.lan.home.", dns.TypeA),
		respValidator: func(t *testing.T, resp *dns.Msg) {
			assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
			assert.Equal(t, "host.lan.home.\t3600\tIN\tA\t192.168.178.56", resp.Answer[0].String())
		},
	},
	{
		// delegate to special dns upstream
		name:    "conditional",
		request: util.NewMsgWithQuestion("host.fritz.box.", dns.TypeA),
		respValidator: func(t *testing.T, resp *dns.Msg) {
			assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
			assert.Equal(t, "host.fritz.box.\t3600\tIN\tA\t192.168.178.2", resp.Answer[0].String())
		},
	},
	{
		// blocking default group
		name:    "blockDefault",
		request: util.NewMsgWithQuestion("doubleclick.net.", dns.TypeA),
		respValidator: func(t *testing.T, resp *dns.Msg) {
			assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
			assert.Equal(t, "doubleclick.net.\t21600\tIN\tA\t0.0.0.0", resp.Answer[0].String())
		},
	},
	{
		// blocking default group with sub domain
		name:    "blockDefaultWithSubdomain",
		request: util.NewMsgWithQuestion("www.bild.de.", dns.TypeA),
		respValidator: func(t *testing.T, resp *dns.Msg) {
			assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
			assert.Equal(t, "www.bild.de.\t21600\tIN\tA\t0.0.0.0", resp.Answer[0].String())
		},
	},
	{
		// no blocking default group with sub domain
		name:    "noBlockDefaultWithSubdomain",
		request: util.NewMsgWithQuestion("bild.de.", dns.TypeA),
		respValidator: func(t *testing.T, resp *dns.Msg) {
			assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
			assert.Equal(t, "bild.de.\t123\tIN\tA\t123.124.122.122", resp.Answer[0].String())
		},
	},
	{
		// white and block default group
		name:    "whiteBlackDefault",
		request: util.NewMsgWithQuestion("heise.de.", dns.TypeA),
		respValidator: func(t *testing.T, resp *dns.Msg) {
			assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
			assert.Equal(t, "heise.de.\t123\tIN\tA\t123.124.122.122", resp.Answer[0].String())
		},
	},
	{
		// no block client whitelist only
		name:           "noBlockWhitelistOnly",
		mockClientName: "clWhitelistOnly",
		request:        util.NewMsgWithQuestion("heise.de.", dns.TypeA),
		respValidator: func(t *testing.T, resp *dns.Msg) {
			assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
			assert.Equal(t, "123.124.122.122", resp.Answer[0].(*dns.A).A.String())
		},
	},
	{
		// block client whitelist only
		name:           "blockWhitelistOnly",
		mockClientName: "clWhitelistOnly",
		request:        util.NewMsgWithQuestion("google.de.", dns.TypeA),
		respValidator: func(t *testing.T, resp *dns.Msg) {
			assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
			assert.Equal(t, "0.0.0.0", resp.Answer[0].(*dns.A).A.String())
		},
	},
	{
		// block client with 2 groups
		name:           "block2groups1",
		mockClientName: "clAdsAndYoutube",
		request:        util.NewMsgWithQuestion("www.bild.de.", dns.TypeA),
		respValidator: func(t *testing.T, resp *dns.Msg) {
			assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
			assert.Equal(t, "0.0.0.0", resp.Answer[0].(*dns.A).A.String())
		},
	},
	{
		// block client with 2 groups
		name:           "block2groups2",
		mockClientName: "clAdsAndYoutube",
		request:        util.NewMsgWithQuestion("youtube.com.", dns.TypeA),
		respValidator: func(t *testing.T, resp *dns.Msg) {
			assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
			assert.Equal(t, "0.0.0.0", resp.Answer[0].(*dns.A).A.String())
		},
	},
	{
		// lient with 1 group: no block if domain in other group
		name:           "noBlockBlacklistOtherGroup",
		mockClientName: "clYoutubeOnly",
		request:        util.NewMsgWithQuestion("www.bild.de.", dns.TypeA),
		respValidator: func(t *testing.T, resp *dns.Msg) {
			assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
			assert.Equal(t, "123.124.122.122", resp.Answer[0].(*dns.A).A.String())
		},
	},
	{
		// block client with 1 group
		name:           "blockBlacklist",
		mockClientName: "clYoutubeOnly",
		request:        util.NewMsgWithQuestion("youtube.com.", dns.TypeA),
		respValidator: func(t *testing.T, resp *dns.Msg) {
			assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
			assert.Equal(t, "0.0.0.0", resp.Answer[0].(*dns.A).A.String())
		},
	},
	{
		// healthcheck
		name:           "healthcheck",
		mockClientName: "c1",
		request:        util.NewMsgWithQuestion("healthcheck.blocky.", dns.TypeA),
		respValidator: func(t *testing.T, resp *dns.Msg) {
			assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
			assert.Empty(t, resp.Answer)
		},
	},
}

//nolint:funlen
func TestDnsRequest(t *testing.T) {
	upstreamGoogle := resolver.TestUDPUpstream(func(request *dns.Msg) *dns.Msg {
		response, err := util.NewMsgWithAnswer(fmt.Sprintf("%s %d %s %s %s",
			util.ExtractDomain(request.Question[0]), 123, "IN", "A", "123.124.122.122"))

		assert.NoError(t, err)
		return response
	})
	upstreamFritzbox := resolver.TestUDPUpstream(func(request *dns.Msg) *dns.Msg {
		response, err := util.NewMsgWithAnswer(fmt.Sprintf("%s %d %s %s %s",
			util.ExtractDomain(request.Question[0]), 3600, "IN", "A", "192.168.178.2"))

		assert.NoError(t, err)
		return response
	})

	upstreamClient := resolver.TestUDPUpstream(func(request *dns.Msg) *dns.Msg {
		response, err := util.NewMsgWithAnswer(fmt.Sprintf("%s %d %s %s %s",
			util.ExtractDomain(request.Question[0]), 3600, "IN", "PTR", mockClientName))

		assert.NoError(t, err)
		return response
	})

	// create server
	server, err := NewServer(&config.Config{
		CustomDNS: config.CustomDNSConfig{
			Mapping: map[string]net.IP{
				"custom.lan": net.ParseIP("192.168.178.55"),
				"lan.home":   net.ParseIP("192.168.178.56"),
			},
		},
		Conditional: config.ConditionalUpstreamConfig{
			Mapping: map[string]config.Upstream{"fritz.box": upstreamFritzbox},
		},
		Blocking: config.BlockingConfig{
			BlackLists: map[string][]string{
				"ads": {
					"../testdata/doubleclick.net.txt",
					"../testdata/www.bild.de.txt",
					"../testdata/heise.de.txt"},
				"youtube": {"../testdata/youtube.com.txt"}},
			WhiteLists: map[string][]string{
				"ads":       {"../testdata/heise.de.txt"},
				"whitelist": {"../testdata/heise.de.txt"},
			},
			ClientGroupsBlock: map[string][]string{
				"default":         {"ads"},
				"clWhitelistOnly": {"whitelist"},
				"clAdsAndYoutube": {"ads", "youtube"},
				"clYoutubeOnly":   {"youtube"},
			},
		},
		Upstream: config.UpstreamConfig{
			ExternalResolvers: []config.Upstream{upstreamGoogle},
		},
		ClientLookup: config.ClientLookupConfig{
			Upstream: upstreamClient,
		},

		Port:     55555,
		HTTPPort: 4000,
	})

	assert.NoError(t, err)

	// start server
	go func() {
		server.Start()
	}()

	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	for _, tt := range tests {
		tst := tt
		t.Run(tt.name, func(t *testing.T) {
			res := server.queryResolver
			for res != nil {
				if t, ok := res.(*resolver.ClientNamesResolver); ok {
					t.FlushCache()
					break
				}
				if c, ok := res.(resolver.ChainedResolver); ok {
					res = c.GetNext()
				} else {
					break
				}
			}

			mockClientName = tst.mockClientName
			response := requestServer(tst.request)

			tst.respValidator(t, response)
		})
	}
}

func Test_Start(t *testing.T) {
	defer func() { logrus.StandardLogger().ExitFunc = nil }()

	var fatal bool

	logrus.StandardLogger().ExitFunc = func(int) { fatal = true }

	// create server
	server, err := NewServer(&config.Config{
		CustomDNS: config.CustomDNSConfig{
			Mapping: map[string]net.IP{
				"custom.lan": net.ParseIP("192.168.178.55"),
				"lan.home":   net.ParseIP("192.168.178.56"),
			},
		},

		Port: 55555,
	})

	assert.NoError(t, err)

	// start server
	go func() {
		server.Start()
	}()

	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	server.Start()

	time.Sleep(100 * time.Millisecond)

	assert.True(t, fatal)
}

func Test_Stop(t *testing.T) {
	defer func() { logrus.StandardLogger().ExitFunc = nil }()

	var fatal bool

	logrus.StandardLogger().ExitFunc = func(int) { fatal = true }

	// create server
	server, err := NewServer(&config.Config{
		CustomDNS: config.CustomDNSConfig{
			Mapping: map[string]net.IP{
				"custom.lan": net.ParseIP("192.168.178.55"),
				"lan.home":   net.ParseIP("192.168.178.56"),
			},
		},

		Port: 55555,
	})

	assert.NoError(t, err)

	// start server
	go func() {
		server.Start()
	}()

	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	server.Stop()

	// stop server, should be ok
	assert.False(t, fatal)

	// stop again, should raise fatal error
	server.Stop()

	assert.True(t, fatal)
}

func BenchmarkServerExternalResolver(b *testing.B) {
	upstreamExternal := resolver.TestUDPUpstream(func(request *dns.Msg) (response *dns.Msg) {
		msg, _ := util.NewMsgWithAnswer(fmt.Sprintf("example.com IN A 123.124.122.122"))
		return msg
	})

	// create server
	server, err := NewServer(&config.Config{
		Upstream: config.UpstreamConfig{
			ExternalResolvers: []config.Upstream{upstreamExternal},
		},
		Port: 55555,
	})

	assert.NoError(b, err)

	// start server
	go func() {
		server.Start()
	}()

	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = requestServer(util.NewMsgWithQuestion("google.de.", dns.TypeA))
		}
	})
}

func requestServer(request *dns.Msg) *dns.Msg {
	conn, err := net.Dial("udp", ":55555")
	if err != nil {
		log.Fatal("could not connect to server: ", err)
	}
	defer conn.Close()

	msg, err := request.Pack()
	if err != nil {
		log.Fatal("can't pack request: ", err)
	}

	_, err = conn.Write(msg)
	if err != nil {
		log.Fatal("can't send request to server: ", err)
	}

	out := make([]byte, 1024)

	if _, err := conn.Read(out); err == nil {
		response := new(dns.Msg)
		err := response.Unpack(out)

		if err != nil {
			log.Fatal("can't unpack response: ", err)
		}

		return response
	}

	log.Fatal("could not read from connection", err)

	return nil
}

func Test_ResolveClientIpUdp(t *testing.T) {
	ip := resolveClientIP(&net.UDPAddr{IP: net.ParseIP("192.168.178.88")})
	assert.Equal(t, net.ParseIP("192.168.178.88"), ip)
}

func Test_ResolveClientIpTcp(t *testing.T) {
	ip := resolveClientIP(&net.TCPAddr{IP: net.ParseIP("192.168.178.88")})
	assert.Equal(t, net.ParseIP("192.168.178.88"), ip)
}
