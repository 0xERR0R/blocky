package config

import (
	"errors"
	"fmt"
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
			err := c.UnmarshalYAML(func(i interface{}) error {
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
			err := c.UnmarshalYAML(func(i interface{}) error {
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
			err := c.UnmarshalYAML(func(i interface{}) error {
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
			err := c.UnmarshalYAML(func(i interface{}) error {
				return errors.New("some err")
			})
			Expect(err).Should(HaveOccurred())
			Expect(err).Should(MatchError("some err"))
		})
	})

	Describe("ZoneFileDNS UnmarshalYAML", func() {
		It("Should parse config as map", func() {
			z := ZoneFileDNS{}
			err := z.UnmarshalYAML(func(i interface{}) error {
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
			err := z.UnmarshalYAML(func(i interface{}) error {
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
			err := z.UnmarshalYAML(func(i interface{}) error {
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
			err := z.UnmarshalYAML(func(i interface{}) error {
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
			err := z.UnmarshalYAML(func(i interface{}) error {
				return fmt.Errorf("Failed to unmarshal")
			})
			Expect(err).Should(HaveOccurred())
			Expect(err).Should(MatchError("Failed to unmarshal"))
		})
	})
})
