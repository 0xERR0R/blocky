package config

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"github.com/creasty/defaults"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"

	"github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/log"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Config", func() {
	var (
		c *Config

		tmpDir *helpertest.TmpFolder
		err    error
	)

	suiteBeforeEach()

	BeforeEach(func() {
		tmpDir = helpertest.NewTmpFolder("config")
	})

	Describe("Deprecated parameters are converted", func() {
		BeforeEach(func() {
			c = new(Config)
			err := defaults.Set(c)
			Expect(err).Should(Succeed())
		})

		When("parameter 'disableIPv6' is set", func() {
			It("should add 'AAAA' to filter.queryTypes", func() {
				c.Deprecated.DisableIPv6 = ptrOf(true)
				c.migrate(logger)
				Expect(hook.Messages).Should(ContainElement(ContainSubstring("disableIPv6")))
				Expect(c.Filtering.QueryTypes).Should(HaveKey(QType(dns.TypeAAAA)))
				Expect(c.Filtering.QueryTypes.Contains(dns.Type(dns.TypeAAAA))).Should(BeTrue())
			})
		})

		When("parameter 'failStartOnListError' is set", func() {
			BeforeEach(func() {
				c.Blocking.Deprecated.FailStartOnListError = ptrOf(true)
			})
			It("should change loading.strategy blocking to failOnError", func() {
				c.Blocking.Loading.Strategy = InitStrategyBlocking
				c.migrate(logger)
				Expect(hook.Messages).Should(ContainElement(ContainSubstring("blocking.loading.strategy")))
				Expect(c.Blocking.Loading.Strategy).Should(Equal(InitStrategyFailOnError))
			})
			It("shouldn't change loading.strategy if set to fast", func() {
				c.Blocking.Loading.Strategy = InitStrategyFast
				c.migrate(logger)
				Expect(hook.Messages).Should(ContainElement(ContainSubstring("blocking.loading.strategy")))
				Expect(c.Blocking.Loading.Strategy).Should(Equal(InitStrategyFast))
			})
		})

		When("parameter 'logLevel' is set", func() {
			It("should convert to log.level", func() {
				c.Deprecated.LogLevel = ptrOf(logrus.DebugLevel)
				c.migrate(logger)
				Expect(hook.Messages).Should(ContainElement(ContainSubstring("log.level")))
				Expect(c.Log.Level).Should(Equal(logrus.DebugLevel))
			})
		})

		When("parameter 'logFormat' is set", func() {
			It("should convert to log.format", func() {
				c.Deprecated.LogFormat = ptrOf(log.FormatTypeJson)
				c.migrate(logger)
				Expect(hook.Messages).Should(ContainElement(ContainSubstring("log.format")))
				Expect(c.Log.Format).Should(Equal(log.FormatTypeJson))
			})
		})

		When("parameter 'logPrivacy' is set", func() {
			It("should convert to log.privacy", func() {
				c.Deprecated.LogPrivacy = ptrOf(true)
				c.migrate(logger)
				Expect(hook.Messages).Should(ContainElement(ContainSubstring("log.privacy")))
				Expect(c.Log.Privacy).Should(BeTrue())
			})
		})

		When("parameter 'logTimestamp' is set", func() {
			It("should convert to log.timestamp", func() {
				c.Deprecated.LogTimestamp = ptrOf(false)
				c.migrate(logger)
				Expect(hook.Messages).Should(ContainElement(ContainSubstring("log.timestamp")))
				Expect(c.Log.Timestamp).Should(BeFalse())
			})
		})

		When("parameter 'port' is set", func() {
			It("should convert to ports.dns", func() {
				ports := ListenConfig([]string{"5333"})
				c.Deprecated.DNSPorts = ptrOf(ports)
				c.migrate(logger)
				Expect(hook.Messages).Should(ContainElement(ContainSubstring("ports.dns")))
				Expect(c.Ports.DNS).Should(Equal(ports))
			})
		})

		When("parameter 'httpPort' is set", func() {
			It("should convert to ports.http", func() {
				ports := ListenConfig([]string{"5333"})
				c.Deprecated.HTTPPorts = ptrOf(ports)
				c.migrate(logger)
				Expect(hook.Messages).Should(ContainElement(ContainSubstring("ports.http")))
				Expect(c.Ports.HTTP).Should(Equal(ports))
			})
		})

		When("parameter 'httpsPort' is set", func() {
			It("should convert to ports.https", func() {
				ports := ListenConfig([]string{"5333"})
				c.Deprecated.HTTPSPorts = ptrOf(ports)
				c.migrate(logger)
				Expect(hook.Messages).Should(ContainElement(ContainSubstring("ports.https")))
				Expect(c.Ports.HTTPS).Should(Equal(ports))
			})
		})

		When("parameter 'tlsPort' is set", func() {
			It("should convert to ports.tls", func() {
				ports := ListenConfig([]string{"5333"})
				c.Deprecated.TLSPorts = ptrOf(ports)
				c.migrate(logger)
				Expect(hook.Messages).Should(ContainElement(ContainSubstring("ports.tls")))
				Expect(c.Ports.TLS).Should(Equal(ports))
			})
		})

		When("parameter 'startVerifyUpstream' is set", func() {
			It("should convert to upstreams.init.strategy", func() {
				c.Deprecated.StartVerifyUpstream = ptrOf(true)
				c.migrate(logger)
				Expect(hook.Messages).Should(ContainElement(ContainSubstring("startVerifyUpstream")))
				Expect(c.Upstreams.Init.Strategy).Should(Equal(InitStrategyFailOnError))
			})
		})
	})

	Describe("Creation of Config", func() {
		When("Test config file will be parsed", func() {
			It("should return a valid config struct", func() {
				confFile := writeConfigYml(tmpDir)

				c, err = LoadConfig(confFile.Path, true)
				Expect(err).Should(Succeed())

				defaultTestFileConfig(c)
			})
		})
		When("Test config file contains a zone file with $INCLUDE", func() {
			When("The config path is set to the config file", func() {
				It("Should support the $INCLUDE directive with a bare filename", func() {
					folder := helpertest.NewTmpFolder("zones")
					folder.CreateStringFile("other.zone", "www 3600 A 1.2.3.4")
					cfgFile := writeConfigYmlWithLocalZoneFile(folder, "other.zone")

					c, err = LoadConfig(cfgFile.Path, true)

					Expect(err).Should(Succeed())
					Expect(c.CustomDNS.Zone.RRs).Should(HaveLen(1))

					Expect(c.CustomDNS.Zone.RRs["www.example.com."]).
						Should(SatisfyAll(
							HaveLen(1),
							ContainElements(
								SatisfyAll(
									helpertest.BeDNSRecord("www.example.com.", helpertest.A, "1.2.3.4"),
									helpertest.HaveTTL(BeNumerically("==", 3600)),
								)),
						))
				})
				It("Should support the $INCLUDE directive with a relative filename", func() {
					folder := helpertest.NewTmpFolder("zones")
					folder.CreateStringFile("other.zone", "www 3600 A 1.2.3.4")
					cfgFile := writeConfigYmlWithLocalZoneFile(folder, "./other.zone")

					c, err = LoadConfig(cfgFile.Path, true)

					Expect(err).Should(Succeed())
					Expect(c.CustomDNS.Zone.RRs).Should(HaveLen(1))

					Expect(c.CustomDNS.Zone.RRs["www.example.com."]).
						Should(SatisfyAll(

							HaveLen(1),
							ContainElements(
								SatisfyAll(
									helpertest.BeDNSRecord("www.example.com.", helpertest.A, "1.2.3.4"),
									helpertest.HaveTTL(BeNumerically("==", 3600)),
								)),
						))
				})
			})
			When("The config path is set to a directory", func() {
				It("Should support the $INCLUDE directive with a bare filename", func() {
					folder := helpertest.NewTmpFolder("zones")
					folder.CreateStringFile("other.zone", "www 3600 A 1.2.3.4")
					writeConfigYmlWithLocalZoneFile(folder, "other.zone")

					c, err = LoadConfig(folder.Path, true)

					Expect(err).Should(Succeed())
					Expect(c.CustomDNS.Zone.RRs).Should(HaveLen(1))

					Expect(c.CustomDNS.Zone.RRs["www.example.com."]).
						Should(SatisfyAll(
							HaveLen(1),
							ContainElements(
								SatisfyAll(
									helpertest.BeDNSRecord("www.example.com.", helpertest.A, "1.2.3.4"),
									helpertest.HaveTTL(BeNumerically("==", 3600)),
								)),
						))
				})
				It("Should support the $INCLUDE directive with a relative filename", func() {
					folder := helpertest.NewTmpFolder("zones")
					folder.CreateStringFile("other.zone", "www 3600 A 1.2.3.4")
					writeConfigYmlWithLocalZoneFile(folder, "./other.zone")

					c, err = LoadConfig(folder.Path, true)

					Expect(err).Should(Succeed())
					Expect(c.CustomDNS.Zone.RRs).Should(HaveLen(1))

					Expect(c.CustomDNS.Zone.RRs["www.example.com."]).
						Should(SatisfyAll(

							HaveLen(1),
							ContainElements(
								SatisfyAll(
									helpertest.BeDNSRecord("www.example.com.", helpertest.A, "1.2.3.4"),
									helpertest.HaveTTL(BeNumerically("==", 3600)),
								)),
						))
				})
			})
		})
		When("Test file does not exist", func() {
			It("should fail", func() {
				_, err := LoadConfig(tmpDir.JoinPath("config-does-not-exist.yaml"), true)
				Expect(err).Should(HaveOccurred())
			})
		})
		When("Multiple config files are used", func() {
			BeforeEach(func() {
				writeConfigDir(tmpDir)
			})

			It("should return a valid config struct", func() {
				c, err := LoadConfig(tmpDir.Path, true)
				Expect(err).Should(Succeed())

				defaultTestFileConfig(c)
			})

			It("should ignore non YAML files", func() {
				tmpDir.CreateStringFile("ignore-me.txt", "THIS SHOULD BE IGNORED!")

				_, err := LoadConfig(tmpDir.Path, true)
				Expect(err).Should(Succeed())
			})

			It("should ignore non regular files", func() {
				tmpDir.CreateSubFolder("subfolder")
				tmpDir.CreateSubFolder("subfolder.yml")

				_, err := LoadConfig(tmpDir.Path, true)
				Expect(err).Should(Succeed())
			})
		})
		When("Config folder does not exist", func() {
			It("should fail", func() {
				_, err := LoadConfig(tmpDir.JoinPath("does-not-exist-config/"), true)
				Expect(err).Should(HaveOccurred())
			})
		})
		When("config file is malformed", func() {
			It("should return error", func() {
				cfgFile := tmpDir.CreateStringFile("config.yml", "malformed_config")

				c, err = LoadConfig(cfgFile.Path, true)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("wrong file structure"))
			})
		})
		When("duration is in wrong format", func() {
			It("should return error", func() {
				cfg := Config{}
				data := `
blocking:
  loading:
    refreshPeriod: wrongduration`
				err := unmarshalConfig(logger, []byte(data), &cfg)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("invalid duration \"wrongduration\""))
			})
		})
		When("CustomDNS hast wrong IP defined", func() {
			It("should return error", func() {
				cfg := Config{}
				data := `customDNS:
  mapping:
    someDomain: 192.168.178.WRONG`
				err := unmarshalConfig(logger, []byte(data), &cfg)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("invalid IP address '192.168.178.WRONG'"))
			})
		})
		When("CustomDNS hast wrong IPv6 defined", func() {
			It("should return error", func() {
				cfg := Config{}
				data := `customDNS:
  mapping:
    someDomain: 2001:MALFORMED:IP:ADDRESS:0000:8a2e:0370:7334`
				err := unmarshalConfig(logger, []byte(data), &cfg)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("invalid IP address '2001:MALFORMED:IP:ADDRESS:0000:8a2e:0370:7334'"))
			})
		})
		When("Conditional mapping hast wrong defined upstreams", func() {
			It("should return error", func() {
				cfg := Config{}
				data := `conditional:
  mapping:
    multiple.resolvers: 192.168.178.1,wrongprotocol:4.4.4.4:53`
				err := unmarshalConfig(logger, []byte(data), &cfg)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("wrong host name 'wrongprotocol:4.4.4.4:53'"))
			})
		})
		When("Wrong upstreams are defined", func() {
			It("should return error", func() {
				cfg := Config{}
				data := `upstream:
  default:
    - 8.8.8.8
    - wrongprotocol:8.8.4.4
    - 1.1.1.1`
				err := unmarshalConfig(logger, []byte(data), &cfg)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("can't convert upstream 'wrongprotocol:8.8.4.4'"))
			})
		})
		When("Wrong filtering is defined", func() {
			It("should return error", func() {
				cfg := Config{}
				data := `filtering:
  queryTypes:
    - invalidqtype
`
				err := unmarshalConfig(logger, []byte(data), &cfg)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("unknown DNS query type: 'invalidqtype'"))
			})
		})

		When("bootstrapDns is defined", func() {
			It("should be backwards compatible to 'single IP syntax'", func() {
				cfg := Config{}
				data := "bootstrapDns: 0.0.0.0"

				err := unmarshalConfig(logger, []byte(data), &cfg)
				Expect(err).Should(Succeed())
				Expect(cfg.BootstrapDNS[0].Upstream.Host).Should(Equal("0.0.0.0"))
			})
			It("should be backwards compatible to 'single item definition'", func() {
				cfg := Config{}
				data := `
bootstrapDns:
  upstream: tcp-tls:dns.example.com
  ips:
    - 0.0.0.0
`
				err := unmarshalConfig(logger, []byte(data), &cfg)
				Expect(err).Should(Succeed())
				Expect(cfg.BootstrapDNS[0].Upstream.Host).Should(Equal("dns.example.com"))
				Expect(cfg.BootstrapDNS[0].IPs).Should(HaveLen(1))
			})
			It("should process list of bootstrap items", func() {
				cfg := Config{}
				data := `
bootstrapDns:
  - upstream: tcp-tls:dns.example.com
    ips:
      - 0.0.0.0
  - upstream: 1.2.3.4
`
				err := unmarshalConfig(logger, []byte(data), &cfg)
				Expect(err).Should(Succeed())
				Expect(cfg.BootstrapDNS).Should(HaveLen(2))
				Expect(cfg.BootstrapDNS[0].Upstream.Host).Should(Equal("dns.example.com"))
				Expect(cfg.BootstrapDNS[0].Upstream.Net).Should(Equal(NetProtocolTcpTls))
				Expect(cfg.BootstrapDNS[0].IPs).Should(HaveLen(1))
				Expect(cfg.BootstrapDNS[1].Upstream.Host).Should(Equal("1.2.3.4"))
				Expect(cfg.BootstrapDNS[1].Upstream.Net).Should(Equal(NetProtocolTcpUdp))
			})
		})

		When("config is not YAML", func() {
			It("should return error", func() {
				cfg := Config{}
				data := `///`
				err := unmarshalConfig(logger, []byte(data), &cfg)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("cannot unmarshal !!str `///`"))
			})
		})

		When("config directory does not exist", func() {
			It("should return error", func() {
				c, err = LoadConfig(tmpDir.JoinPath("config.yml"), true)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("no such file or directory"))
			})

			It("should use default config if config is not mandatory", func() {
				c, err = LoadConfig(tmpDir.JoinPath("config.yml"), false)

				Expect(err).Should(Succeed())
				Expect(c.Log.Level).Should(Equal(logrus.InfoLevel))
			})
		})
	})

	Describe("Parsing", func() {
		Context("upstream", func() {
			It("should create the upstream struct with data", func() {
				u := &Upstream{}
				err := u.UnmarshalText([]byte("tcp+udp:1.2.3.4"))
				Expect(err).Should(Succeed())
				Expect(u.Net).Should(Equal(NetProtocolTcpUdp))
				Expect(u.Host).Should(Equal("1.2.3.4"))
				Expect(u.Port).Should(BeNumerically("==", 53))
			})

			It("should fail if the upstream is in wrong format", func() {
				u := &Upstream{}
				err := u.UnmarshalText([]byte("invalid!"))
				Expect(err).Should(HaveOccurred())
			})
		})
		Context("ListenConfig", func() {
			It("should parse and split valid string config", func() {
				l := &ListenConfig{}
				err := l.UnmarshalText([]byte("55,:56"))
				Expect(err).Should(Succeed())
				Expect(*l).Should(HaveLen(2))
				Expect(*l).Should(ContainElements("55", ":56"))
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

	Describe("SourceLoadingConfig", func() {
		var cfg SourceLoading

		BeforeEach(func() {
			cfg = SourceLoading{
				Concurrency:   12,
				RefreshPeriod: Duration(time.Hour),
			}
		})

		Describe("LogConfig", func() {
			It("should log configuration", func() {
				cfg.LogConfig(logger)

				Expect(hook.Calls).ShouldNot(BeEmpty())
				Expect(hook.Messages).Should(ContainElements(
					ContainSubstring("concurrency = 12"),
					ContainSubstring("refresh = every 1 hour"),
				))
			})
			When("refresh is disabled", func() {
				BeforeEach(func() {
					cfg.RefreshPeriod = Duration(-1)
				})

				It("should reflect that", func() {
					logger.Logger.Level = logrus.InfoLevel

					cfg.LogConfig(logger)

					Expect(hook.Calls).ShouldNot(BeEmpty())
					Expect(hook.Messages).ShouldNot(ContainElement(ContainSubstring("refresh = disabled")))

					logger.Logger.Level = logrus.TraceLevel

					cfg.LogConfig(logger)

					Expect(hook.Calls).ShouldNot(BeEmpty())
					Expect(hook.Messages).Should(ContainElement(ContainSubstring("refresh = disabled")))
				})
			})
		})
	})

	Describe("InitStrategy", func() {
		Describe("InitStrategyBlocking", func() {
			It("runs in the current goroutine", func() {
				sut := InitStrategyBlocking
				panicVal := new(int)

				defer func() {
					// recover will catch the panic if it happened in the same goroutine
					Expect(recover()).Should(BeIdenticalTo(panicVal))
				}()

				_ = sut.Do(context.Background(), func(context.Context) error {
					return errors.New("trigger `logErr`")
				}, func(err error) {
					panic(panicVal)
				})

				Fail("unreachable")
			})

			It("logs errors and doesn't return them", func() {
				sut := InitStrategyBlocking
				expectedErr := errors.New("test")

				err := sut.Do(context.Background(), func(context.Context) error {
					return expectedErr
				}, func(err error) {
					Expect(err).Should(MatchError(expectedErr))
				})

				Expect(err).Should(Succeed())
			})

			It("logs panics and doesn't convert them to errors", func() {
				sut := InitStrategyBlocking

				logged := false
				err := sut.Do(context.Background(), func(context.Context) error {
					panic(struct{}{})
				}, func(err error) {
					logged = true
					Expect(err).Should(MatchError(ContainSubstring("panic")))
				})

				Expect(err).Should(Succeed())
				Expect(logged).Should(BeTrue())
			})
		})

		Describe("InitStrategyFailOnError", func() {
			It("runs in the current goroutine", func() {
				sut := InitStrategyFailOnError
				panicVal := new(int)

				defer func() {
					// recover will catch the panic if it happened in the same goroutine
					Expect(recover()).Should(BeIdenticalTo(panicVal))
				}()

				_ = sut.Do(context.Background(), func(context.Context) error {
					return errors.New("trigger `logErr`")
				}, func(err error) {
					panic(panicVal)
				})

				Fail("unreachable")
			})

			It("logs errors and returns them", func() {
				sut := InitStrategyFailOnError
				expectedErr := errors.New("test")

				err := sut.Do(context.Background(), func(context.Context) error {
					return expectedErr
				}, func(err error) {
					Expect(err).Should(MatchError(expectedErr))
				})

				Expect(err).Should(MatchError(expectedErr))
			})

			It("returns logs panics and converts them to errors", func() {
				sut := InitStrategyFailOnError

				logged := false
				err := sut.Do(context.Background(), func(context.Context) error {
					panic(struct{}{})
				}, func(err error) {
					logged = true
					Expect(err).Should(MatchError(ContainSubstring("panic")))
				})

				Expect(err).Should(HaveOccurred())
				Expect(logged).Should(BeTrue())
			})
		})

		Describe("InitStrategyFast", func() {
			It("runs in a new goroutine", func() {
				sut := InitStrategyFast
				events := make(chan string)
				wait := make(chan struct{})

				err := sut.Do(context.Background(), func(context.Context) error {
					events <- "start"
					<-wait
					events <- "done"

					return nil
				}, nil)

				Eventually(events, "50ms").Should(Receive(Equal("start")))
				Expect(err).Should(Succeed())
				Consistently(events).ShouldNot(Receive())
				close(wait)
				Eventually(events, "50ms").Should(Receive(Equal("done")))
			})

			It("logs errors", func() {
				sut := InitStrategyFast
				expectedErr := errors.New("test")
				wait := make(chan struct{})

				err := sut.Do(context.Background(), func(context.Context) error {
					return expectedErr
				}, func(err error) {
					Expect(err).Should(MatchError(expectedErr))
					close(wait)
				})

				Expect(err).Should(Succeed())
				Eventually(wait, "50ms").Should(BeClosed())
			})

			It("logs panics", func() {
				sut := InitStrategyFast
				expectedErr := errors.New("test")
				wait := make(chan struct{})

				err := sut.Do(context.Background(), func(context.Context) error {
					return expectedErr
				}, func(err error) {
					Expect(err).Should(MatchError(expectedErr))
					close(wait)
				})

				Expect(err).Should(Succeed())
				Eventually(wait, "50ms").Should(BeClosed())
			})
		})
	})

	Describe("BootstrapDNSConfig", func() {
		It("is not enabled when empty", func() {
			var sut BootstrapDNS

			Expect(sut.IsEnabled()).Should(BeFalse())
		})

		It("is enabled if non empty", func() {
			sut := BootstrapDNS{
				BootstrappedUpstream{},
				BootstrappedUpstream{},
			}

			Expect(sut.IsEnabled()).Should(BeTrue())
		})

		It("LogConfig panics", func() {
			sut := BootstrapDNS{}

			Expect(func() {
				sut.LogConfig(logger)
			}).Should(Panic())
		})
	})

	Describe("SourceLoadingConfig", func() {
		var (
			ctx      context.Context
			cancelFn context.CancelFunc
		)
		BeforeEach(func() {
			ctx, cancelFn = context.WithCancel(context.Background())
			DeferCleanup(cancelFn)
		})
		It("handles panics", func() {
			sut := SourceLoading{
				Init: Init{Strategy: InitStrategyFailOnError},
			}

			panicMsg := "panic value"

			err := sut.StartPeriodicRefresh(ctx, func(context.Context) error {
				panic(panicMsg)
			}, func(err error) {
				Expect(err).Should(MatchError(ContainSubstring(panicMsg)))
			})

			Expect(err).Should(MatchError(ContainSubstring(panicMsg)))
		})

		It("periodically calls refresh", func() {
			sut := SourceLoading{
				Init:          Init{Strategy: InitStrategyFast},
				RefreshPeriod: Duration(5 * time.Millisecond),
			}

			panicMsg := "panic value"
			calls := make(chan int32, 3)

			var call atomic.Int32

			err := sut.StartPeriodicRefresh(ctx, func(context.Context) error {
				call := call.Add(1)
				calls <- call

				if call == 3 {
					panic(panicMsg)
				}

				return nil
			}, func(err error) {
				defer GinkgoRecover()

				Expect(err).Should(MatchError(ContainSubstring(panicMsg)))
				Expect(call.Load()).Should(Equal(int32(3)))
			})

			Expect(err).Should(Succeed())
			Eventually(calls, "50ms").Should(Receive(Equal(int32(1))))
			Eventually(calls, "50ms").Should(Receive(Equal(int32(2))))
			Eventually(calls, "50ms").Should(Receive(Equal(int32(3))))
		})
	})

	Describe("WithDefaults", func() {
		It("use valid defaults", func() {
			type T struct {
				X int `default:"1"`
			}

			t, err := WithDefaults[T]()
			Expect(err).Should(Succeed())
			Expect(t.X).Should(Equal(1))
		})

		It("return an error if the tag is invalid", func() {
			type T struct {
				X struct{} `default:"fail"`
			}

			_, err := WithDefaults[T]()
			Expect(err).Should(HaveOccurred())
		})
	})

	Describe("Documentation config", func() {
		It("should not use deprecated options", func() {
			logger, hook := log.NewMockEntry()

			_, err := loadConfig(logger, "../docs/config.yml", true)
			Expect(err).Should(Succeed())
			Expect(hook.Messages).ShouldNot(ContainElement(ContainSubstring("deprecated")))
		})
	})
})

func defaultTestFileConfig(config *Config) {
	Expect(config.Ports.DNS).Should(Equal(ListenConfig{"55553", ":55554", "[::1]:55555"}))
	Expect(config.Upstreams.Init.Strategy).Should(Equal(InitStrategyFailOnError))
	Expect(config.Upstreams.UserAgent).Should(Equal("testBlocky"))
	Expect(config.Upstreams.Groups["default"]).Should(HaveLen(3))
	Expect(config.Upstreams.Groups["default"][0].Host).Should(Equal("8.8.8.8"))
	Expect(config.Upstreams.Groups["default"][1].Host).Should(Equal("8.8.4.4"))
	Expect(config.Upstreams.Groups["default"][2].Host).Should(Equal("1.1.1.1"))
	Expect(config.CustomDNS.Mapping).Should(HaveLen(2))

	duckDNSEntry := config.CustomDNS.Mapping["my.duckdns.org"][0]
	duckDNSA := duckDNSEntry.(*dns.A)
	Expect(duckDNSA.A).Should(Equal(net.ParseIP("192.168.178.3")))

	multipleIpsEntry := config.CustomDNS.Mapping["multiple.ips"][0]
	multipleIpsA := multipleIpsEntry.(*dns.A)
	Expect(multipleIpsA.A).Should(Equal(net.ParseIP("192.168.178.3")))

	multipleIpsEntry = config.CustomDNS.Mapping["multiple.ips"][1]
	multipleIpsA = multipleIpsEntry.(*dns.A)
	Expect(multipleIpsA.A).Should(Equal(net.ParseIP("192.168.178.4")))

	multipleIpsEntry = config.CustomDNS.Mapping["multiple.ips"][2]
	multipleIpsAAAA := multipleIpsEntry.(*dns.AAAA)
	Expect(multipleIpsAAAA.AAAA).Should(Equal(net.ParseIP("2001:db8:85a3:8d3:1319:8a2e:370:7344")))

	Expect(config.Conditional.Mapping.Upstreams).Should(HaveLen(2))
	Expect(config.Conditional.Mapping.Upstreams["fritz.box"]).Should(HaveLen(1))
	Expect(config.Conditional.Mapping.Upstreams["multiple.resolvers"]).Should(HaveLen(2))
	Expect(config.ClientLookup.Upstream.Host).Should(Equal("192.168.178.1"))
	Expect(config.ClientLookup.SingleNameOrder).Should(Equal([]uint{2, 1}))
	Expect(config.Blocking.Denylists).Should(HaveLen(2))
	Expect(config.Blocking.Allowlists).Should(HaveLen(1))
	Expect(config.Blocking.ClientGroupsBlock).Should(HaveLen(2))
	Expect(config.Blocking.BlockTTL).Should(Equal(Duration(time.Minute)))
	Expect(config.Blocking.Loading.RefreshPeriod).Should(Equal(Duration(2 * time.Hour)))
	Expect(config.Filtering.QueryTypes).Should(HaveLen(2))
	Expect(config.FQDNOnly.Enable).Should(BeTrue())

	Expect(config.Caching.MaxCachingTime).Should(BeZero())
	Expect(config.Caching.MinCachingTime).Should(BeZero())

	Expect(config.MinTLSServeVer).Should(Equal(TLSVersion13))
	Expect(config.MinTLSServeVer).Should(BeEquivalentTo(tls.VersionTLS13))
}

func writeConfigYml(tmpDir *helpertest.TmpFolder) *helpertest.TmpFile {
	return tmpDir.CreateStringFile("config.yml",
		"upstreams:",
		"  userAgent: testBlocky",
		"  init:",
		"    strategy: failOnError",
		"  groups:",
		"    default:",
		"      - tcp+udp:8.8.8.8",
		"      - tcp+udp:8.8.4.4",
		"      - 1.1.1.1",
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
		"fqdnOnly:",
		"  enable: true",
		"blocking:",
		"  denylists:",
		"    ads:",
		"      - https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
		"      - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
		"      - https://mirror1.malwaredomains.com/files/justdomains",
		"      - http://sysctl.org/cameleon/hosts",
		"      - https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist",
		"      - https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
		"    special:",
		"      - https://hosts-file.net/ad_servers.txt",
		"  allowlists:",
		"    ads:",
		"      - allowlist.txt",
		"  clientGroupsBlock:",
		"    default:",
		"      - ads",
		"      - special",
		"    Laptop-D.fritz.box:",
		"      - ads",
		"  blockTTL: 1m",
		"  loading:",
		"    refreshPeriod: 120",
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
		"minTlsServeVersion: 1.3",
	)
}

func writeConfigYmlWithLocalZoneFile(tmpDir *helpertest.TmpFolder, includeStr string) *helpertest.TmpFile {
	return tmpDir.CreateStringFile("config.yml",
		"upstreams:",
		"  userAgent: testBlocky",
		"  init:",
		"    strategy: failOnError",
		"  groups:",
		"    default:",
		"      - tcp+udp:8.8.8.8",
		"      - tcp+udp:8.8.4.4",
		"      - 1.1.1.1",
		"customDNS:",
		"  zone: |",
		"    $ORIGIN example.com.",
		"    $INCLUDE "+includeStr,
		"filtering:",
		"  queryTypes:",
		"    - AAAA",
		"    - A",
		"fqdnOnly:",
		"  enable: true",
		"port: 55553,:55554,[::1]:55555",
		"logLevel: debug",
		"minTlsServeVersion: 1.3",
	)
}

func writeConfigDir(tmpDir *helpertest.TmpFolder) {
	tmpDir.CreateStringFile("config1.yaml",
		"upstreams:",
		"  userAgent: testBlocky",
		"  init:",
		"    strategy: failOnError",
		"  groups:",
		"    default:",
		"      - tcp+udp:8.8.8.8",
		"      - tcp+udp:8.8.4.4",
		"      - 1.1.1.1",
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
	)

	tmpDir.CreateStringFile("config2.yaml",
		"blocking:",
		"  denylists:",
		"    ads:",
		"      - https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
		"      - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
		"      - https://mirror1.malwaredomains.com/files/justdomains",
		"      - http://sysctl.org/cameleon/hosts",
		"      - https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist",
		"      - https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
		"    special:",
		"      - https://hosts-file.net/ad_servers.txt",
		"  allowlists:",
		"    ads:",
		"      - allowlist.txt",
		"  clientGroupsBlock:",
		"    default:",
		"      - ads",
		"      - special",
		"    Laptop-D.fritz.box:",
		"      - ads",
		"  blockTTL: 1m",
		"  loading:",
		"    refreshPeriod: 120",
		"clientLookup:",
		"  upstream: 192.168.178.1",
		"  singleNameOrder:",
		"    - 2",
		"    - 1",
		"fqdnOnly:",
		"  enable: true",
		"queryLog:",
		"  type: csv-client",
		"  target: /opt/log",
		"port: 55553,:55554,[::1]:55555",
		"logLevel: debug",
		"minTlsServeVersion: 1.3",
	)
}

// Tiny helper to get a new pointer with a value.
//
// Avoids needing 2 lines: `x := new(T)` and `*x = val`
func ptrOf[T any](val T) *T {
	return &val
}
