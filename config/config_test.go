package config

import (
	. "blocky/log"
	"io/ioutil"
	"net"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("Config", func() {
	Describe("Creation of Config", func() {
		When("Test config file will be parsed", func() {
			It("should return a valid config struct", func() {
				err := os.Chdir("../testdata")
				Expect(err).Should(Succeed())

				cfg := NewConfig("config.yml", true)

				Expect(cfg.Port).Should(Equal("55555"))
				Expect(cfg.Upstream.ExternalResolvers["default"]).Should(HaveLen(3))
				Expect(cfg.Upstream.ExternalResolvers["default"][0].Host).Should(Equal("8.8.8.8"))
				Expect(cfg.Upstream.ExternalResolvers["default"][1].Host).Should(Equal("8.8.4.4"))
				Expect(cfg.Upstream.ExternalResolvers["default"][2].Host).Should(Equal("1.1.1.1"))
				Expect(cfg.CustomDNS.Mapping.HostIPs).Should(HaveLen(2))
				Expect(cfg.CustomDNS.Mapping.HostIPs["my.duckdns.org"][0]).Should(Equal(net.ParseIP("192.168.178.3")))
				Expect(cfg.CustomDNS.Mapping.HostIPs["multiple.ips"][0]).Should(Equal(net.ParseIP("192.168.178.3")))
				Expect(cfg.CustomDNS.Mapping.HostIPs["multiple.ips"][1]).Should(Equal(net.ParseIP("192.168.178.4")))
				Expect(cfg.CustomDNS.Mapping.HostIPs["multiple.ips"][2]).Should(Equal(
					net.ParseIP("2001:0db8:85a3:08d3:1319:8a2e:0370:7344")))
				Expect(cfg.Conditional.Mapping.Upstreams).Should(HaveLen(2))
				Expect(cfg.Conditional.Mapping.Upstreams["fritz.box"]).Should(HaveLen(1))
				Expect(cfg.Conditional.Mapping.Upstreams["multiple.resolvers"]).Should(HaveLen(2))
				Expect(cfg.ClientLookup.Upstream.Host).Should(Equal("192.168.178.1"))
				Expect(cfg.ClientLookup.SingleNameOrder).Should(Equal([]uint{2, 1}))
				Expect(cfg.Blocking.BlackLists).Should(HaveLen(2))
				Expect(cfg.Blocking.WhiteLists).Should(HaveLen(1))
				Expect(cfg.Blocking.ClientGroupsBlock).Should(HaveLen(2))

				Expect(cfg.Caching.MaxCachingTime).Should(Equal(0))
				Expect(cfg.Caching.MinCachingTime).Should(Equal(0))
			})
		})
		When("config file is malformed", func() {
			It("should log with fatal and exit", func() {

				dir, err := ioutil.TempDir("", "blocky")
				defer os.Remove(dir)
				Expect(err).Should(Succeed())
				err = os.Chdir(dir)
				Expect(err).Should(Succeed())
				err = ioutil.WriteFile("config.yml", []byte("malformed_config"), 0600)
				Expect(err).Should(Succeed())

				defer func() { Log().ExitFunc = nil }()

				var fatal bool

				Log().ExitFunc = func(int) { fatal = true }

				_ = NewConfig("config.yml", true)
				Expect(fatal).Should(BeTrue())
			})
		})
		When("config directory does not exist", func() {
			It("should log with fatal and exit if config is mandatory", func() {
				err := os.Chdir("../..")
				Expect(err).Should(Succeed())

				defer func() { Log().ExitFunc = nil }()

				var fatal bool

				Log().ExitFunc = func(int) { fatal = true }
				_ = NewConfig("config.yml", true)

				Expect(fatal).Should(BeTrue())
			})

			It("should use default config if config is not mandatory", func() {
				err := os.Chdir("../..")
				Expect(err).Should(Succeed())

				cfg := NewConfig("config.yml", false)

				Expect(cfg.LogLevel).Should(Equal("info"))
			})
		})
	})

	DescribeTable("parse upstream string",
		func(in string, wantResult Upstream, wantErr bool) {
			result, err := ParseUpstream(in)
			if wantErr {
				Expect(err).Should(HaveOccurred())
			} else {
				Expect(err).Should(Succeed())
			}
			Expect(result).Should(Equal(wantResult))
		},
		Entry("udp with port",
			"udp:4.4.4.4:531",
			Upstream{Net: "tcp+udp", Host: "4.4.4.4", Port: 531},
			false),
		Entry("udp without port, use default",
			"udp:4.4.4.4",
			Upstream{Net: "tcp+udp", Host: "4.4.4.4", Port: 53},
			false),
		Entry("tcp with port",
			"tcp:4.4.4.4:4711",
			Upstream{Net: "tcp+udp", Host: "4.4.4.4", Port: 4711},
			false),
		Entry("tcp without port, use default",
			"tcp:4.4.4.4",
			Upstream{Net: "tcp+udp", Host: "4.4.4.4", Port: 53},
			false),
		Entry("tcp-tls without port, use default",
			"tcp-tls:4.4.4.4",
			Upstream{Net: "tcp-tls", Host: "4.4.4.4", Port: 853},
			false),
		Entry("DoH without port, use default",
			"https:4.4.4.4",
			Upstream{Net: "https", Host: "4.4.4.4", Port: 443},
			false),
		Entry("DoH with port",
			"https:4.4.4.4:888",
			Upstream{Net: "https", Host: "4.4.4.4", Port: 888},
			false),
		Entry("DoH named",
			"https://dns.google/dns-query",
			Upstream{Net: "https", Host: "dns.google", Port: 443, Path: "/dns-query"},
			false),
		Entry("DoH named, path with multiple slashes",
			"https://dns.google/dns-query/a/b",
			Upstream{Net: "https", Host: "dns.google", Port: 443, Path: "/dns-query/a/b"},
			false),
		Entry("DoH named with port",
			"https://dns.google:888/dns-query",
			Upstream{Net: "https", Host: "dns.google", Port: 888, Path: "/dns-query"},
			false),
		Entry("empty",
			"",
			Upstream{Net: ""},
			false),
		Entry("udpIpv6WithPort",
			"udp:[fd00::6cd4:d7e0:d99d:2952]:53",
			Upstream{Net: "tcp+udp", Host: "fd00::6cd4:d7e0:d99d:2952", Port: 53},
			false),
		Entry("udpIpv6WithPort2",
			"udp://[2001:4860:4860::8888]:53",
			Upstream{Net: "tcp+udp", Host: "2001:4860:4860::8888", Port: 53},
			false),
		Entry("default net, default port",
			"1.1.1.1",
			Upstream{Net: "tcp+udp", Host: "1.1.1.1", Port: 53},
			false),
		Entry("default net with port",
			"1.1.1.1:153",
			Upstream{Net: "tcp+udp", Host: "1.1.1.1", Port: 153},
			false),
		Entry("with negative port",
			"tcp:4.4.4.4:-1",
			nil,
			true),
		Entry("with invalid port",
			"tcp:4.4.4.4:65536",
			nil,
			true),
		Entry("with not numeric port",
			"tcp:4.4.4.4:A636",
			nil,
			true),
		Entry("with wrong protocol",
			"bla:4.4.4.4:53",
			nil,
			true),
		Entry("tcp+udp",
			"tcp+udp:1.1.1.1:53",
			Upstream{Net: "tcp+udp", Host: "1.1.1.1", Port: 53},
			false),
		Entry("tcp+udp default port",
			"tcp+udp:1.1.1.1",
			Upstream{Net: "tcp+udp", Host: "1.1.1.1", Port: 53},
			false),
	)
})
