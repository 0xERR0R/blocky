package config

import (
	"errors"
	"fmt"
	"net"
	"strings"

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
www6 3600 AAAA 2001:0db8:85a3:0000:0000:8a2e:0370:7334
cname 3600 CNAME www
				`)

				return nil
			})
			Expect(err).Should(Succeed())
			Expect(z).Should(HaveLen(3))

			for url, records := range z {
				if url == "www.example.com." {
					Expect(records).Should(HaveLen(1))

					record, isA := records[0].(*dns.A)

					Expect(isA).Should(BeTrue())
					Expect(record.A).Should(Equal(net.ParseIP("1.2.3.4")))
				} else if url == "www6.example.com." {
					Expect(records).Should(HaveLen(1))

					record, isAAAA := records[0].(*dns.AAAA)

					Expect(isAAAA).Should(BeTrue())
					Expect(record.AAAA).Should(Equal(net.ParseIP("2001:db8:85a3::8a2e:370:7334")))
				} else if url == "cname.example.com." {
					Expect(records).Should(HaveLen(1))

					record, isCNAME := records[0].(*dns.CNAME)

					Expect(isCNAME).Should(BeTrue())
					Expect(record.Target).Should(Equal("www.example.com."))
				} else {
					Fail("unexpected record")
				}
			}
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
