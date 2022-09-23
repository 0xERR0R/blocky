package config

import (
	"errors"
	"net"
	"time"

	"github.com/miekg/dns"

	"github.com/0xERR0R/blocky/helpertest"
	. "github.com/0xERR0R/blocky/log"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Config", func() {
	var (
		tmpDir *helpertest.TmpFolder
		err    error
	)

	BeforeEach(func() {
		tmpDir = helpertest.NewTmpFolder("config")
		Expect(tmpDir.Error).Should(Succeed())
		DeferCleanup(tmpDir.Clean)
	})

	Describe("Creation of Config", func() {
		When("Test config file will be parsed", func() {
			It("should return a valid config struct", func() {
				confFile := writeConfigYml(tmpDir)
				Expect(confFile.Error).Should(Succeed())

				_, err = LoadConfig(confFile.Path, true)
				Expect(err).Should(Succeed())

				defaultTestFileConfig()
			})
		})
		When("Test file does not exist", func() {
			It("should fail", func() {
				_, err := LoadConfig(tmpDir.JoinPath("config-does-not-exist.yaml"), true)
				Expect(err).Should(Not(Succeed()))
			})
		})
		When("Multiple config files are used", func() {
			It("should return a valid config struct", func() {
				err = writeConfigDir(tmpDir)
				Expect(err).Should(Succeed())

				_, err := LoadConfig(tmpDir.Path, true)
				Expect(err).Should(Succeed())

				defaultTestFileConfig()
			})

			It("should ignore non YAML files", func() {
				err = writeConfigDir(tmpDir)
				Expect(err).Should(Succeed())

				tmpDir.CreateStringFile("ignore-me.txt", "THIS SHOULD BE IGNORED!")

				_, err := LoadConfig(tmpDir.Path, true)
				Expect(err).Should(Succeed())
			})

			It("should ignore non regular files", func() {
				err = writeConfigDir(tmpDir)
				Expect(err).Should(Succeed())

				tmpDir.CreateSubFolder("subfolder")
				tmpDir.CreateSubFolder("subfolder.yml")

				_, err := LoadConfig(tmpDir.Path, true)
				Expect(err).Should(Succeed())
			})
		})
		When("Config folder does not exist", func() {
			It("should fail", func() {
				_, err := LoadConfig(tmpDir.JoinPath("does-not-exist-config/"), true)
				Expect(err).Should(Not(Succeed()))
			})
		})
		When("config file is malformed", func() {
			It("should return error", func() {
				cfgFile := tmpDir.CreateStringFile("config.yml", "malformed_config")
				Expect(cfgFile.Error).Should(Succeed())

				_, err = LoadConfig(cfgFile.Path, true)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("wrong file structure"))
			})
		})
		When("duration is in wrong format", func() {
			It("should return error", func() {
				cfg := Config{}
				data :=
					`blocking:
  refreshPeriod: wrongduration`
				err := unmarshalConfig([]byte(data), &cfg)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("invalid duration \"wrongduration\""))
			})
		})
		When("CustomDNS hast wrong IP defined", func() {
			It("should return error", func() {
				cfg := Config{}
				data :=
					`customDNS:
  mapping:
    someDomain: 192.168.178.WRONG`
				err := unmarshalConfig([]byte(data), &cfg)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("invalid IP address '192.168.178.WRONG'"))
			})
		})
		When("Conditional mapping hast wrong defined upstreams", func() {
			It("should return error", func() {
				cfg := Config{}
				data :=
					`conditional:
  mapping:
    multiple.resolvers: 192.168.178.1,wrongprotocol:4.4.4.4:53`
				err := unmarshalConfig([]byte(data), &cfg)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("wrong host name 'wrongprotocol:4.4.4.4:53'"))
			})
		})
		When("Wrong upstreams are defined", func() {
			It("should return error", func() {
				cfg := Config{}
				data :=
					`upstream:
  default:
    - 8.8.8.8
    - wrongprotocol:8.8.4.4
    - 1.1.1.1`
				err := unmarshalConfig([]byte(data), &cfg)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("can't convert upstream 'wrongprotocol:8.8.4.4'"))
			})
		})
		When("Wrong filtering is defined", func() {
			It("should return error", func() {
				cfg := Config{}
				data :=
					`filtering:
  queryTypes:
    - invalidqtype
`
				err := unmarshalConfig([]byte(data), &cfg)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("unknown DNS query type: 'invalidqtype'"))
			})
		})

		When("bootstrapDns is defined", func() {
			It("should is backwards compatible", func() {
				cfg := Config{}
				data := "bootstrapDns: 0.0.0.0"

				err := unmarshalConfig([]byte(data), &cfg)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(cfg.BootstrapDNS.Upstream.Host).Should(Equal("0.0.0.0"))
			})
			It("should is backwards compatible", func() {
				cfg := Config{}
				data := `
bootstrapDns:
  upstream: tcp-tls:dns.example.com
  ips:
    - 0.0.0.0
`
				err := unmarshalConfig([]byte(data), &cfg)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(cfg.BootstrapDNS.Upstream.Host).Should(Equal("dns.example.com"))
				Expect(cfg.BootstrapDNS.IPs).Should(HaveLen(1))
			})
		})

		When("config is not YAML", func() {
			It("should return error", func() {
				cfg := Config{}
				data :=
					`///`
				err := unmarshalConfig([]byte(data), &cfg)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("cannot unmarshal !!str `///`"))
			})
		})

		When("Deprecated parameter 'disableIPv6' is set", func() {
			It("should add 'AAAA' to filter.queryTypes", func() {
				c := &Config{
					DisableIPv6: true,
				}
				validateConfig(c)
				Expect(c.Filtering.QueryTypes).Should(HaveKey(QType(dns.TypeAAAA)))
				Expect(c.Filtering.QueryTypes.Contains(dns.Type(dns.TypeAAAA))).Should(BeTrue())
			})
		})

		When("Deprecated parameter 'failStartOnListError' is set", func() {
			var (
				c Config
			)
			BeforeEach(func() {
				c = Config{
					Blocking: BlockingConfig{
						FailStartOnListError: true,
						StartStrategy:        StartStrategyTypeBlocking,
					},
				}
			})
			It("should change StartStrategy blocking to failOnError", func() {
				validateConfig(&c)
				Expect(c.Blocking.StartStrategy).Should(Equal(StartStrategyTypeFailOnError))
			})
			It("shouldn't change StartStrategy if set to fast", func() {
				c.Blocking.StartStrategy = StartStrategyTypeFast
				validateConfig(&c)
				Expect(c.Blocking.StartStrategy).Should(Equal(StartStrategyTypeFast))
			})
		})

		When("config directory does not exist", func() {
			It("should return error", func() {
				_, err = LoadConfig(tmpDir.JoinPath("config.yml"), true)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("no such file or directory"))

			})

			It("should use default config if config is not mandatory", func() {
				_, err = LoadConfig(tmpDir.JoinPath("config.yml"), false)

				Expect(err).Should(Succeed())
				Expect(config.LogLevel).Should(Equal(LevelInfo))
			})
		})
	})

	Describe("YAML parsing", func() {
		Context("upstream", func() {
			It("should create the upstream struct with data", func() {
				u := &Upstream{}
				err := u.UnmarshalYAML(func(i interface{}) error {
					*i.(*string) = "tcp+udp:1.2.3.4"

					return nil

				})
				Expect(err).Should(Succeed())
				Expect(u.Net).Should(Equal(NetProtocolTcpUdp))
				Expect(u.Host).Should(Equal("1.2.3.4"))
				Expect(u.Port).Should(BeNumerically("==", 53))
			})

			It("should fail if the upstream is in wrong format", func() {
				u := &Upstream{}
				err := u.UnmarshalYAML(func(i interface{}) error {
					return errors.New("some err")

				})
				Expect(err).Should(HaveOccurred())
			})
		})
		Context("ListenConfig", func() {
			It("should parse and split valid string config", func() {
				l := &ListenConfig{}
				err := l.UnmarshalYAML(func(i interface{}) error {
					*i.(*string) = "55,:56"

					return nil
				})
				Expect(err).Should(Succeed())
				Expect(*l).Should(HaveLen(2))
				Expect(*l).Should(ContainElements("55", ":56"))
			})
			It("should fail on error", func() {
				l := &ListenConfig{}
				err := l.UnmarshalYAML(func(i interface{}) error {
					return errors.New("some err")
				})
				Expect(err).Should(HaveOccurred())
			})
		})
		Context("Duration", func() {
			It("should parse duration with unit", func() {
				d := Duration(0)
				err := d.UnmarshalYAML(func(i interface{}) error {
					*i.(*string) = "1m20s"

					return nil
				})
				Expect(err).Should(Succeed())
				Expect(d).Should(Equal(Duration(80 * time.Second)))
				Expect(d.String()).Should(Equal("1 minute 20 seconds"))
			})
			It("should fail if duration is in wrong format", func() {
				d := Duration(0)
				err := d.UnmarshalYAML(func(i interface{}) error {
					*i.(*string) = "wrong"

					return nil
				})
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(MatchError("time: invalid duration \"wrong\""))

			})
			It("should fail if wrong YAML format", func() {
				d := Duration(0)
				err := d.UnmarshalYAML(func(i interface{}) error {
					return errors.New("some err")
				})
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(MatchError("some err"))
			})

		})
		Context("ConditionalUpstreamMapping", func() {
			It("Should parse config as map", func() {
				c := &ConditionalUpstreamMapping{}
				err := c.UnmarshalYAML(func(i interface{}) error {
					*i.(*map[string]string) = map[string]string{"key": "1.2.3.4"}

					return nil
				})
				Expect(err).Should(Succeed())
				Expect(c.Upstreams).Should(HaveLen(1))
				Expect(c.Upstreams["key"]).Should(HaveLen(1))
				Expect(c.Upstreams["key"][0]).Should(Equal(Upstream{
					Net: NetProtocolTcpUdp, Host: "1.2.3.4", Port: 53}))
			})
			It("should fail if wrong YAML format", func() {
				c := &ConditionalUpstreamMapping{}
				err := c.UnmarshalYAML(func(i interface{}) error {
					return errors.New("some err")
				})
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(MatchError("some err"))
			})
		})
		Context("CustomDNSMapping", func() {
			It("Should parse config as map", func() {
				c := &CustomDNSMapping{}
				err := c.UnmarshalYAML(func(i interface{}) error {
					*i.(*map[string]string) = map[string]string{"key": "1.2.3.4"}

					return nil
				})
				Expect(err).Should(Succeed())
				Expect(c.HostIPs).Should(HaveLen(1))
				Expect(c.HostIPs["key"]).Should(HaveLen(1))
				Expect(c.HostIPs["key"][0]).Should(Equal(net.ParseIP("1.2.3.4")))
			})
			It("should fail if wrong YAML format", func() {
				c := &CustomDNSMapping{}
				err := c.UnmarshalYAML(func(i interface{}) error {
					return errors.New("some err")
				})
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(MatchError("some err"))
			})
		})
		Context("QueryTyoe", func() {
			It("Should parse existing DNS type as string", func() {
				t := QType(0)
				err := t.UnmarshalYAML(func(i interface{}) error {
					*i.(*string) = "AAAA"

					return nil
				})
				Expect(err).Should(Succeed())
				Expect(t).Should(Equal(QType(dns.TypeAAAA)))
				Expect(t.String()).Should(Equal("AAAA"))
			})
			It("should fail if DNS type does not exist", func() {
				t := QType(0)
				err := t.UnmarshalYAML(func(i interface{}) error {
					*i.(*string) = "WRONGTYPE"

					return nil
				})
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("unknown DNS query type: 'WRONGTYPE'"))
			})
			It("should fail if wrong YAML format", func() {
				d := QType(0)
				err := d.UnmarshalYAML(func(i interface{}) error {
					return errors.New("some err")
				})
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(MatchError("some err"))
			})
		})
	})

	DescribeTable("Upstream parsing",
		func(in string, wantResult Upstream, wantErr bool) {
			result, err := ParseUpstream(in)
			if wantErr {
				Expect(err).Should(HaveOccurred(), in)
			} else {
				Expect(err).Should(Succeed(), in)
			}
			Expect(result).Should(Equal(wantResult), in)
		},
		Entry("tcp+udp with port",
			"4.4.4.4:531",
			Upstream{Net: NetProtocolTcpUdp, Host: "4.4.4.4", Port: 531},
			false),
		Entry("tcp+udp without port, use default",
			"4.4.4.4",
			Upstream{Net: NetProtocolTcpUdp, Host: "4.4.4.4", Port: 53},
			false),
		Entry("tcp+udp with port",
			"tcp+udp:4.4.4.4:4711",
			Upstream{Net: NetProtocolTcpUdp, Host: "4.4.4.4", Port: 4711},
			false),
		Entry("tcp without port, use default",
			"4.4.4.4",
			Upstream{Net: NetProtocolTcpUdp, Host: "4.4.4.4", Port: 53},
			false),
		Entry("tcp-tls without port, use default",
			"tcp-tls:4.4.4.4",
			Upstream{Net: NetProtocolTcpTls, Host: "4.4.4.4", Port: 853},
			false),
		Entry("tcp-tls with common name",
			"tcp-tls:1.1.1.2#security.cloudflare-dns.com",
			Upstream{Net: NetProtocolTcpTls, Host: "1.1.1.2", Port: 853, CommonName: "security.cloudflare-dns.com"},
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
			"tcp+udp:[fd00::6cd4:d7e0:d99d:2952]:53",
			Upstream{Net: NetProtocolTcpUdp, Host: "fd00::6cd4:d7e0:d99d:2952", Port: 53},
			false),
		Entry("udpIpv6WithPort2",
			"[2001:4860:4860::8888]:53",
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

	DescribeTable("Upstream string representation",
		func(upstream Upstream, canonical string) {
			Expect(upstream.String()).To(Equal(canonical))

			if !upstream.IsDefault() {
				roundTripped, err := ParseUpstream(canonical)
				Expect(err).Should(Succeed())
				Expect(roundTripped).Should(Equal(upstream))
			}
		},
		Entry("Default",
			Upstream{}, "no upstream",
		),
		Entry("tcp+udp with port",
			Upstream{Net: NetProtocolTcpUdp, Host: "localhost", Port: 531},
			"tcp+udp:localhost:531",
		),
		Entry("tcp+udp default port",
			Upstream{Net: NetProtocolTcpUdp, Host: "localhost", Port: 53},
			"tcp+udp:localhost",
		),
		Entry("tcp-tls with port",
			Upstream{Net: NetProtocolTcpTls, Host: "localhost", Port: 888},
			"tcp-tls:localhost:888",
		),
		Entry("tcp-tls default port",
			Upstream{Net: NetProtocolTcpTls, Host: "localhost", Port: 853},
			"tcp-tls:localhost",
		),
		Entry("tcp+udp with other default port",
			Upstream{Net: NetProtocolTcpUdp, Host: "localhost", Port: 443},
			"tcp+udp:localhost:443"),
		Entry("https with port",
			Upstream{Net: NetProtocolHttps, Host: "localhost", Port: 888},
			"https://localhost:888",
		),
		Entry("https with path",
			Upstream{Net: NetProtocolHttps, Host: "localhost", Port: 443, Path: "/dns-query"},
			"https://localhost/dns-query",
		),
		Entry("https with path and port",
			Upstream{Net: NetProtocolHttps, Host: "localhost", Port: 888, Path: "/dns-query"},
			"https://localhost:888/dns-query",
		),
		Entry("tcp+udp IPv4 with port",
			Upstream{Net: NetProtocolTcpUdp, Host: "127.0.0.1", Port: 531},
			"tcp+udp:127.0.0.1:531",
		),
		Entry("tcp+udp IPv4 default port",
			Upstream{Net: NetProtocolTcpUdp, Host: "127.0.0.1", Port: 53},
			"tcp+udp:127.0.0.1",
		),
		Entry("tcp-tls IPv6 with port",
			Upstream{Net: NetProtocolTcpTls, Host: "fd00::6cd4:d7e0:d99d:2952", Port: 531},
			"tcp-tls:[fd00::6cd4:d7e0:d99d:2952]:531",
		),
		Entry("tcp-tls IPv6 default port",
			Upstream{Net: NetProtocolTcpTls, Host: "fd00::6cd4:d7e0:d99d:2952", Port: 853},
			"tcp-tls:[fd00::6cd4:d7e0:d99d:2952]",
		),
	)

	Describe("QTypeSet", func() {
		It("new should insert given qTypes", func() {
			set := NewQTypeSet(dns.Type(dns.TypeA))
			Expect(set).Should(HaveKey(QType(dns.TypeA)))
			Expect(set.Contains(dns.Type(dns.TypeA))).Should(BeTrue())

			Expect(set).ShouldNot(HaveKey(QType(dns.TypeAAAA)))
			Expect(set.Contains(dns.Type(dns.TypeAAAA))).ShouldNot(BeTrue())
		})

		It("should insert given qTypes", func() {
			set := NewQTypeSet()

			Expect(set).ShouldNot(HaveKey(QType(dns.TypeAAAA)))
			Expect(set.Contains(dns.Type(dns.TypeAAAA))).ShouldNot(BeTrue())

			set.Insert(dns.Type(dns.TypeAAAA))

			Expect(set).Should(HaveKey(QType(dns.TypeAAAA)))
			Expect(set.Contains(dns.Type(dns.TypeAAAA))).Should(BeTrue())
		})
	})
})

func defaultTestFileConfig() {
	Expect(config.DNSPorts).Should(Equal(ListenConfig{"55553", ":55554", "[::1]:55555"}))
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
	Expect(config.Filtering.QueryTypes).Should(HaveLen(2))

	Expect(config.Caching.MaxCachingTime).Should(Equal(Duration(0)))
	Expect(config.Caching.MinCachingTime).Should(Equal(Duration(0)))

	Expect(config.DoHUserAgent).Should(Equal("testBlocky"))
	Expect(config.MinTLSServeVer).Should(Equal("1.3"))
	Expect(config.StartVerifyUpstream).Should(BeFalse())

	Expect(GetConfig()).Should(Not(BeNil()))
}

func writeConfigYml(tmpDir *helpertest.TmpFolder) *helpertest.TmpFile {
	return tmpDir.CreateStringFile("config.yml",
		"upstream:",
		"  default:",
		"    - tcp+udp:8.8.8.8",
		"    - tcp+udp:8.8.4.4",
		"    - 1.1.1.1",
		"customDNS:",
		"  mapping:",
		"    my.duckdns.org: 192.168.178.3",
		"    multiple.ips: 192.168.178.3,192.168.178.4,2001:0db8:85a3:08d3:1319:8a2e:0370:7344",
		"conditional:",
		"  mapping:",
		"    fritz.box: tcp+udp:192.168.178.1",
		"    multiple.resolvers: tcp+udp:192.168.178.1,tcp+udp:192.168.178.2",
		"filtering:",
		"  queryTypes:",
		"    - AAAA",
		"    - A",
		"blocking:",
		"  blackLists:",
		"    ads:",
		"      - https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
		"      - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
		"      - https://mirror1.malwaredomains.com/files/justdomains",
		"      - http://sysctl.org/cameleon/hosts",
		"      - https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist",
		"      - https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
		"    special:",
		"      - https://hosts-file.net/ad_servers.txt",
		"  whiteLists:",
		"    ads:",
		"      - whitelist.txt",
		"  clientGroupsBlock:",
		"    default:",
		"      - ads",
		"      - special",
		"    Laptop-D.fritz.box:",
		"      - ads",
		"  blockTTL: 1m",
		"  refreshPeriod: 120",
		"clientLookup:",
		"  upstream: 192.168.178.1",
		"  singleNameOrder:",
		"    - 2",
		"    - 1",
		"queryLog:",
		"  type: csv-client",
		"  target: /opt/log",
		"port: 55553,:55554,[::1]:55555",
		"logLevel: debug",
		"dohUserAgent: testBlocky",
		"minTlsServeVersion: 1.3",
		"startVerifyUpstream: false")
}

func writeConfigDir(tmpDir *helpertest.TmpFolder) error {
	f1 := tmpDir.CreateStringFile("config1.yaml",
		"upstream:",
		"  default:",
		"    - tcp+udp:8.8.8.8",
		"    - tcp+udp:8.8.4.4",
		"    - 1.1.1.1",
		"customDNS:",
		"  mapping:",
		"    my.duckdns.org: 192.168.178.3",
		"    multiple.ips: 192.168.178.3,192.168.178.4,2001:0db8:85a3:08d3:1319:8a2e:0370:7344",
		"conditional:",
		"  mapping:",
		"    fritz.box: tcp+udp:192.168.178.1",
		"    multiple.resolvers: tcp+udp:192.168.178.1,tcp+udp:192.168.178.2",
		"filtering:",
		"  queryTypes:",
		"    - AAAA",
		"    - A")
	if f1.Error != nil {
		return f1.Error
	}

	f2 := tmpDir.CreateStringFile("config2.yaml",
		"blocking:",
		"  blackLists:",
		"    ads:",
		"      - https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
		"      - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
		"      - https://mirror1.malwaredomains.com/files/justdomains",
		"      - http://sysctl.org/cameleon/hosts",
		"      - https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist",
		"      - https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
		"    special:",
		"      - https://hosts-file.net/ad_servers.txt",
		"  whiteLists:",
		"    ads:",
		"      - whitelist.txt",
		"  clientGroupsBlock:",
		"    default:",
		"      - ads",
		"      - special",
		"    Laptop-D.fritz.box:",
		"      - ads",
		"  blockTTL: 1m",
		"  refreshPeriod: 120",
		"clientLookup:",
		"  upstream: 192.168.178.1",
		"  singleNameOrder:",
		"    - 2",
		"    - 1",
		"queryLog:",
		"  type: csv-client",
		"  target: /opt/log",
		"port: 55553,:55554,[::1]:55555",
		"logLevel: debug",
		"dohUserAgent: testBlocky",
		"minTlsServeVersion: 1.3",
		"startVerifyUpstream: false")

	return f2.Error
}
