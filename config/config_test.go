package config

import (
	"io/ioutil"
	"net"
	"os"
	"time"

	"github.com/0xERR0R/blocky/helpertest"

	. "github.com/0xERR0R/blocky/log"
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

				LoadConfig("config.yml", true)

				Expect(config.Port).Should(Equal("55555"))
				Expect(config.Upstream.ExternalResolvers["default"]).Should(HaveLen(3))
				Expect(config.Upstream.ExternalResolvers["default"][0].Host).Should(Equal("8.8.8.8"))
				Expect(config.Upstream.ExternalResolvers["default"][1].Host).Should(Equal("8.8.4.4"))
				Expect(config.Upstream.ExternalResolvers["default"][2].Host).Should(Equal("1.1.1.1"))
				Expect(config.CustomDNS.Mapping.HostIPs).Should(HaveLen(2))
				Expect(config.CustomDNS.Mapping.HostIPs["my.duckdns.org"][0]).Should(Equal(net.ParseIP("192.168.178.3")))
				Expect(config.CustomDNS.Mapping.HostIPs["multiple.ips"][0]).Should(Equal(net.ParseIP("192.168.178.3")))
				Expect(config.CustomDNS.Mapping.HostIPs["multiple.ips"][1]).Should(Equal(net.ParseIP("192.168.178.4")))
				Expect(config.CustomDNS.Mapping.HostIPs["multiple.ips"][2]).Should(Equal(
					net.ParseIP("2001:0db8:85a3:08d3:1319:8a2e:0370:7344")))
				Expect(config.Conditional.Mapping.Upstreams).Should(HaveLen(2))
				Expect(config.Conditional.Mapping.Upstreams["fritz.box"]).Should(HaveLen(1))
				Expect(config.Conditional.Mapping.Upstreams["multiple.resolvers"]).Should(HaveLen(2))
				Expect(config.ClientLookup.Upstream.Host).Should(Equal("192.168.178.1"))
				Expect(config.ClientLookup.SingleNameOrder).Should(Equal([]uint{2, 1}))
				Expect(config.Blocking.BlackLists).Should(HaveLen(2))
				Expect(config.Blocking.WhiteLists).Should(HaveLen(1))
				Expect(config.Blocking.ClientGroupsBlock).Should(HaveLen(2))
				Expect(config.Blocking.BlockTTL).Should(Equal(Duration(time.Minute)))
				Expect(config.Blocking.RefreshPeriod).Should(Equal(Duration(2 * time.Hour)))

				Expect(config.Caching.MaxCachingTime).Should(Equal(Duration(0)))
				Expect(config.Caching.MinCachingTime).Should(Equal(Duration(0)))

				Expect(GetConfig()).Should(Not(BeNil()))

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

				helpertest.ShouldLogFatal(func() {
					LoadConfig("config.yml", true)
				})
			})
		})
		When("duration is in wrong format", func() {
			It("should log with fatal and exit", func() {
				cfg := Config{}
				data :=
					`blocking:
  refreshPeriod: wrongduration`
				helpertest.ShouldLogFatal(func() {
					unmarshalConfig([]byte(data), cfg)
				})
			})
		})
		When("CustomDNS hast wrong IP defined", func() {
			It("should log with fatal and exit", func() {
				cfg := Config{}
				data :=
					`customDNS:
  mapping:
    someDomain: 192.168.178.WRONG`
				helpertest.ShouldLogFatal(func() {
					unmarshalConfig([]byte(data), cfg)
				})
			})
		})
		When("Conditional mapping hast wrong defined upstreams", func() {
			It("should log with fatal and exit", func() {
				cfg := Config{}
				data :=
					`conditional:
  mapping:
    multiple.resolvers: udp:192.168.178.1,wongprotocol:4.4.4.4:53`
				helpertest.ShouldLogFatal(func() {
					unmarshalConfig([]byte(data), cfg)
				})
			})
		})
		When("Wrong upstreams are defined", func() {
			It("should log with fatal and exit", func() {
				cfg := Config{}
				data :=
					`upstream:
  default:
    - udp:8.8.8.8
    - wrongprotocol:8.8.4.4
    - udp:1.1.1.1`
				helpertest.ShouldLogFatal(func() {
					unmarshalConfig([]byte(data), cfg)
				})
			})
		})

		When("config is not YAML", func() {
			It("should log with fatal and exit", func() {
				cfg := Config{}
				data :=
					`///`
				helpertest.ShouldLogFatal(func() {
					unmarshalConfig([]byte(data), cfg)
				})
			})
		})

		When("deprecated querylog.dir parameter is used", func() {
			It("should be mapped to csv writer", func() {
				By("per client", func() {
					c := &Config{
						QueryLog: QueryLogConfig{
							Dir:       "/somedir",
							PerClient: true,
						}}
					validateConfig(c)

					Expect(c.QueryLog.Target).Should(Equal("/somedir"))
					Expect(c.QueryLog.Type).Should(Equal(QueryLogTypeCsvClient))
				})

				By("one file", func() {
					c := &Config{
						QueryLog: QueryLogConfig{
							Dir:       "/somedir",
							PerClient: false,
						}}
					validateConfig(c)

					Expect(c.QueryLog.Target).Should(Equal("/somedir"))
					Expect(c.QueryLog.Type).Should(Equal(QueryLogTypeCsv))
				})

			})
		})

		When("deprecated httpsCertFile/httpsKeyFile parameter is used", func() {
			It("should be mapped to certFile/keyFile", func() {

				c := &Config{
					HTTPKeyFile:  "key",
					HTTPCertFile: "cert",
				}
				validateConfig(c)

				Expect(c.KeyFile).Should(Equal("key"))
				Expect(c.CertFile).Should(Equal("cert"))
			})
		})

		When("TlsPort is defined", func() {
			It("certFile/keyFile must be set", func() {

				By("certFile/keyFile not set", func() {
					c := &Config{
						TLSPort: "953",
					}
					helpertest.ShouldLogFatal(func() {
						validateConfig(c)
					})
				})

				By("certFile/keyFile set", func() {
					c := &Config{
						TLSPort:  "953",
						KeyFile:  "key",
						CertFile: "cert",
					}
					validateConfig(c)
				})
			})
		})

		When("HttpsPort is defined", func() {
			It("certFile/keyFile must be set", func() {

				By("certFile/keyFile not set", func() {
					c := &Config{
						HTTPSPort: "443",
					}
					helpertest.ShouldLogFatal(func() {
						validateConfig(c)
					})
				})

				By("certFile/keyFile set", func() {
					c := &Config{
						TLSPort:  "443",
						KeyFile:  "key",
						CertFile: "cert",
					}
					validateConfig(c)
				})
			})
		})

		When("config directory does not exist", func() {
			It("should log with fatal and exit if config is mandatory", func() {
				err := os.Chdir("../..")
				Expect(err).Should(Succeed())

				defer func() { Log().ExitFunc = nil }()

				var fatal bool

				Log().ExitFunc = func(int) { fatal = true }
				LoadConfig("config.yml", true)

				Expect(fatal).Should(BeTrue())
			})

			It("should use default config if config is not mandatory", func() {
				err := os.Chdir("../..")
				Expect(err).Should(Succeed())

				LoadConfig("config.yml", false)

				Expect(config.LogLevel).Should(Equal(LevelInfo))
			})
		})
	})

	DescribeTable("parse upstream string",
		func(in string, wantResult Upstream, wantErr bool) {
			result, err := ParseUpstream(in)
			if wantErr {
				Expect(err).Should(HaveOccurred(), in)
			} else {
				Expect(err).Should(Succeed(), in)
			}
			Expect(result).Should(Equal(wantResult), in)
		},
		Entry("udp with port",
			"udp:4.4.4.4:531",
			Upstream{Net: NetProtocolTcpUdp, Host: "4.4.4.4", Port: 531},
			false),
		Entry("udp without port, use default",
			"udp:4.4.4.4",
			Upstream{Net: NetProtocolTcpUdp, Host: "4.4.4.4", Port: 53},
			false),
		Entry("tcp with port",
			"tcp:4.4.4.4:4711",
			Upstream{Net: NetProtocolTcpUdp, Host: "4.4.4.4", Port: 4711},
			false),
		Entry("tcp without port, use default",
			"tcp:4.4.4.4",
			Upstream{Net: NetProtocolTcpUdp, Host: "4.4.4.4", Port: 53},
			false),
		Entry("tcp-tls without port, use default",
			"tcp-tls:4.4.4.4",
			Upstream{Net: NetProtocolTcpTls, Host: "4.4.4.4", Port: 853},
			false),
		Entry("DoH without port, use default",
			"https:4.4.4.4",
			Upstream{Net: NetProtocolHttps, Host: "4.4.4.4", Port: 443},
			false),
		Entry("DoH with port",
			"https:4.4.4.4:888",
			Upstream{Net: NetProtocolHttps, Host: "4.4.4.4", Port: 888},
			false),
		Entry("DoH named",
			"https://dns.google/dns-query",
			Upstream{Net: NetProtocolHttps, Host: "dns.google", Port: 443, Path: "/dns-query"},
			false),
		Entry("DoH named, path with multiple slashes",
			"https://dns.google/dns-query/a/b",
			Upstream{Net: NetProtocolHttps, Host: "dns.google", Port: 443, Path: "/dns-query/a/b"},
			false),
		Entry("DoH named with port",
			"https://dns.google:888/dns-query",
			Upstream{Net: NetProtocolHttps, Host: "dns.google", Port: 888, Path: "/dns-query"},
			false),
		Entry("empty",
			"",
			Upstream{Net: 0},
			true),
		Entry("udpIpv6WithPort",
			"udp:[fd00::6cd4:d7e0:d99d:2952]:53",
			Upstream{Net: NetProtocolTcpUdp, Host: "fd00::6cd4:d7e0:d99d:2952", Port: 53},
			false),
		Entry("udpIpv6WithPort2",
			"udp:[2001:4860:4860::8888]:53",
			Upstream{Net: NetProtocolTcpUdp, Host: "2001:4860:4860::8888", Port: 53},
			false),
		Entry("default net, default port",
			"1.1.1.1",
			Upstream{Net: NetProtocolTcpUdp, Host: "1.1.1.1", Port: 53},
			false),
		Entry("wrong host name",
			"host$name",
			Upstream{},
			true),
		Entry("default net with port",
			"1.1.1.1:153",
			Upstream{Net: NetProtocolTcpUdp, Host: "1.1.1.1", Port: 153},
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
			Upstream{Net: NetProtocolTcpUdp, Host: "1.1.1.1", Port: 53},
			false),
		Entry("tcp+udp default port",
			"tcp+udp:1.1.1.1",
			Upstream{Net: NetProtocolTcpUdp, Host: "1.1.1.1", Port: 53},
			false),
		Entry("defaultIpv6Short",
			"2620:fe::fe",
			Upstream{Net: NetProtocolTcpUdp, Host: "2620:fe::fe", Port: 53},
			false),
		Entry("defaultIpv6Short2",
			"2620:fe::9",
			Upstream{Net: NetProtocolTcpUdp, Host: "2620:fe::9", Port: 53},
			false),
		Entry("defaultIpv6WithPort",
			"[2620:fe::9]:55",
			Upstream{Net: NetProtocolTcpUdp, Host: "2620:fe::9", Port: 55},
			false),
	)
})
