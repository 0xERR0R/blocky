package config

import (
	"errors"
	"net"
	"strings"

	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/creasty/defaults"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("CustomDNSConfig", func() {
	var cfg CustomDNS

	suiteBeforeEach()

	BeforeEach(func() {
		cfg = CustomDNS{
			Mapping: CustomDNSMapping{
				"custom.domain": {&dns.A{A: net.ParseIP("192.168.143.123")}},
				"ip6.domain":    {&dns.AAAA{AAAA: net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334")}},
				"multiple.ips": {
					&dns.A{A: net.ParseIP("192.168.143.123")},
					&dns.A{A: net.ParseIP("192.168.143.125")},
					&dns.AAAA{AAAA: net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334")},
				},
			},
		}
	})

	Describe("IsEnabled", func() {
		It("should be false by default", func() {
			cfg := CustomDNS{}
			Expect(defaults.Set(&cfg)).Should(Succeed())

			Expect(cfg.IsEnabled()).Should(BeFalse())
		})

		When("enabled", func() {
			It("should be true", func() {
				Expect(cfg.IsEnabled()).Should(BeTrue())
			})
		})

		When("disabled", func() {
			It("should be false", func() {
				cfg := CustomDNS{}

				Expect(cfg.IsEnabled()).Should(BeFalse())
			})
		})
	})

	Describe("LogConfig", func() {
		It("should log configuration", func() {
			cfg.LogConfig(logger)

			Expect(hook.Calls).ShouldNot(BeEmpty())
			Expect(hook.Messages).Should(ContainElements(
				ContainSubstring("custom.domain = "),
				ContainSubstring("ip6.domain = "),
				ContainSubstring("multiple.ips = "),
			))
		})
	})

	Describe("CustomDNSEntries UnmarshalYAML", func() {
		It("Should parse config as map", func() {
			c := CustomDNSEntries{}
			err := c.UnmarshalYAML(func(i any) error {
				*i.(*string) = "1.2.3.4"

				return nil
			})
			Expect(err).Should(Succeed())
			Expect(c).Should(HaveLen(1))

			aRecord := c[0].(*dns.A)
			Expect(aRecord.A).Should(Equal(net.ParseIP("1.2.3.4")))
		})

		It("Should parse multiple ips as comma separated string", func() {
			c := CustomDNSEntries{}
			err := c.UnmarshalYAML(func(i any) error {
				*i.(*string) = "1.2.3.4,2.3.4.5"

				return nil
			})
			Expect(err).Should(Succeed())
			Expect(c).Should(HaveLen(2))

			Expect(c[0].(*dns.A).A).Should(Equal(net.ParseIP("1.2.3.4")))
			Expect(c[1].(*dns.A).A).Should(Equal(net.ParseIP("2.3.4.5")))
		})

		It("Should parse multiple ips as comma separated string with whitespace", func() {
			c := CustomDNSEntries{}
			err := c.UnmarshalYAML(func(i any) error {
				*i.(*string) = "1.2.3.4, 2.3.4.5 ,   3.4.5.6"

				return nil
			})
			Expect(err).Should(Succeed())
			Expect(c).Should(HaveLen(3))

			Expect(c[0].(*dns.A).A).Should(Equal(net.ParseIP("1.2.3.4")))
			Expect(c[1].(*dns.A).A).Should(Equal(net.ParseIP("2.3.4.5")))
			Expect(c[2].(*dns.A).A).Should(Equal(net.ParseIP("3.4.5.6")))
		})

		It("should fail if wrong YAML format", func() {
			c := &CustomDNSEntries{}
			err := c.UnmarshalYAML(func(i any) error {
				return errors.New("some err")
			})
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("some err"))
		})
	})

	Describe("ZoneFileDNS UnmarshalYAML", func() {
		It("Should parse config as map", func() {
			z := ZoneFileDNS{}
			err := z.UnmarshalYAML(func(i any) error {
				*i.(*string) = strings.TrimSpace(`
$ORIGIN example.com.
www 3600 A 1.2.3.4
www 3600 AAAA 2001:0db8:85a3:0000:0000:8a2e:0370:7334
www6 3600 AAAA 2001:0db8:85a3:0000:0000:8a2e:0370:7334
cname 3600 CNAME www
				`)

				return nil
			})
			Expect(err).Should(Succeed())
			Expect(z.RRs).Should(HaveLen(3))

			Expect(z.RRs["www.example.com."]).
				Should(SatisfyAll(
					HaveLen(2),
					ContainElements(
						SatisfyAll(
							BeDNSRecord("www.example.com.", A, "1.2.3.4"),
							HaveTTL(BeNumerically("==", 3600)),
						),
						SatisfyAll(
							BeDNSRecord("www.example.com.", AAAA, "2001:db8:85a3::8a2e:370:7334"),
							HaveTTL(BeNumerically("==", 3600)),
						))))

			Expect(z.RRs["www6.example.com."]).
				Should(SatisfyAll(
					HaveLen(1),
					ContainElements(
						SatisfyAll(
							BeDNSRecord("www6.example.com.", AAAA, "2001:db8:85a3::8a2e:370:7334"),
							HaveTTL(BeNumerically("==", 3600)),
						))))

			Expect(z.RRs["cname.example.com."]).
				Should(SatisfyAll(
					HaveLen(1),
					ContainElements(
						SatisfyAll(
							BeDNSRecord("cname.example.com.", CNAME, "www.example.com."),
							HaveTTL(BeNumerically("==", 3600)),
						))))
		})

		It("Should support the $INCLUDE directive with an absolute path", func() {
			folder := NewTmpFolder("zones")
			file := folder.CreateStringFile("other.zone", "www 3600 A 1.2.3.4")

			z := ZoneFileDNS{}
			err := z.UnmarshalYAML(func(i any) error {
				*i.(*string) = strings.TrimSpace(`
$ORIGIN example.com.
$INCLUDE ` + file.Path)

				return nil
			})
			Expect(err).Should(Succeed())
			Expect(z.RRs).Should(HaveLen(1))

			Expect(z.RRs["www.example.com."]).
				Should(SatisfyAll(

					HaveLen(1),
					ContainElements(
						SatisfyAll(
							BeDNSRecord("www.example.com.", A, "1.2.3.4"),
							HaveTTL(BeNumerically("==", 3600)),
						)),
				))
		})

		It("Should return an error if the zone file is malformed", func() {
			z := ZoneFileDNS{}
			err := z.UnmarshalYAML(func(i any) error {
				*i.(*string) = strings.TrimSpace(`
$ORIGIN example.com.
www A 1.2.3.4
				`)

				return nil
			})
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("dns: missing TTL with no previous value"))
		})
		It("Should return an error if a relative record is provided without an origin", func() {
			z := ZoneFileDNS{}
			err := z.UnmarshalYAML(func(i any) error {
				*i.(*string) = strings.TrimSpace(`
$TTL 3600
www A 1.2.3.4
				`)

				return nil
			})
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("dns: bad owner name: \"www\""))
		})
		It("Should return an error if the unmarshall function returns an error", func() {
			z := ZoneFileDNS{}
			err := z.UnmarshalYAML(func(i any) error {
				return errors.New("Failed to unmarshal")
			})
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("Failed to unmarshal"))
		})
	})

	Describe("clientMapping", func() {
		var tmpDir *TmpFolder

		BeforeEach(func() {
			tmpDir = NewTmpFolder("config")
		})

		load := func(lines ...string) (*Config, error) {
			cfgFile := tmpDir.CreateStringFile("config.yml", lines...)

			return LoadConfigWithLogger(logger, cfgFile.Path, true)
		}

		It("parses per-client mappings next to the global one", func() {
			c, err := load(
				"customDNS:",
				"  mapping:",
				"    printer.lan: 192.168.178.3",
				"  clientMapping:",
				"    192.168.68.0/22:",
				"      www.domain.io: 192.168.1.75",
				"    'laptop*, 10.0.0.1':",
				"      www.domain.io: 100.64.0.5,2001:db8::5",
			)
			Expect(err).Should(Succeed())

			Expect(c.CustomDNS.Mapping).Should(HaveKey("printer.lan"))
			Expect(c.CustomDNS.ClientMapping).Should(HaveLen(2))
			entries := c.CustomDNS.ClientMapping["192.168.68.0/22"]["www.domain.io"]
			Expect(entries).Should(HaveLen(1))
			Expect(entries[0]).Should(BeAssignableToTypeOf(&dns.A{}))
			Expect(entries[0].(*dns.A).A.String()).Should(Equal("192.168.1.75"))
			Expect(c.CustomDNS.ClientMapping["laptop*, 10.0.0.1"]["www.domain.io"]).Should(HaveLen(2))
			Expect(c.CustomDNS.IsEnabled()).Should(BeTrue())
			Expect(hook.Messages).ShouldNot(ContainElement(ContainSubstring("does not match schema")))
		})

		It("enables custom DNS on its own", func() {
			cfg := CustomDNS{ClientMapping: CustomDNSClientMapping{"laptop": CustomDNSMapping{}}}

			Expect(cfg.IsEnabled()).Should(BeTrue())
		})

		It("logs every client's entries", func() {
			cfg.ClientMapping = CustomDNSClientMapping{
				"192.168.68.0/22": {"www.domain.io": {&dns.A{A: net.ParseIP("192.168.1.75")}}},
			}

			cfg.LogConfig(logger)

			Expect(hook.Messages).Should(ContainElements(
				"clientMapping:",
				"  192.168.68.0/22:",
				ContainSubstring("    www.domain.io = "),
			))
		})

		DescribeTable("rejects keys that cannot name a client",
			func(key, expected string) {
				_, err := load(
					"customDNS:",
					"  clientMapping:",
					"    '"+key+"':",
					"      www.domain.io: 192.168.1.75",
				)
				Expect(err).Should(MatchError(SatisfyAll(
					ContainSubstring("customDNS.clientMapping"),
					ContainSubstring(expected),
				)))
			},
			Entry("bad CIDR", "192.168.68.0/33", "invalid CIDR '192.168.68.0/33'"),
			Entry("bad IPv4", "192.168.1.300", "invalid IP address '192.168.1.300'"),
			Entry("bad IPv6", "2001:db8::g", "invalid IP address '2001:db8::g'"),
			Entry("bad pattern", "laptop[", "invalid client name pattern 'laptop['"),
			Entry("empty part", "laptop,", "empty client identifier"),
			Entry("default", "default", "use customDNS.mapping for every client"),
		)

		It("rejects a client listed under two keys", func() {
			_, err := load(
				"customDNS:",
				"  clientMapping:",
				"    Laptop, 10.0.0.1:",
				"      www.domain.io: 192.168.1.75",
				"    laptop:",
				"      www.domain.io: 192.168.1.76",
			)
			Expect(err).Should(MatchError(ContainSubstring(
				"client 'laptop' is listed under both 'Laptop, 10.0.0.1' and 'laptop'")))
		})

		It("compares IPs and CIDRs in canonical form", func() {
			_, err := load(
				"customDNS:",
				"  clientMapping:",
				"    '2001:DB8:0::1':",
				"      www.domain.io: 192.168.1.75",
				"    '10.0.0.0/8, 2001:db8::1':",
				"      www.domain.io: 192.168.1.76",
			)
			Expect(err).Should(MatchError(ContainSubstring("client '2001:db8::1' is listed under both")))
		})
	})

	Describe("ParseClientIdentifiers", func() {
		It("normalizes every identifier of a key", func() {
			Expect(ParseClientIdentifiers(" Laptop* ,10.1.2.3/8,2001:DB8::1,192.168.1.2")).Should(Equal(
				[]string{"laptop*", "10.0.0.0/8", "2001:db8::1", "192.168.1.2"}))
		})

		It("takes digits without a dot for a client name", func() {
			Expect(ParseClientIdentifiers("42")).Should(Equal([]string{"42"}))
		})

		It("returns the identifiers it parsed along with the first error", func() {
			ids, err := ParseClientIdentifiers("laptop,10.0.0.0/33,phone")

			Expect(ids).Should(Equal([]string{"laptop", "phone"}))
			Expect(err).Should(MatchError("invalid CIDR '10.0.0.0/33'"))
		})
	})
})
