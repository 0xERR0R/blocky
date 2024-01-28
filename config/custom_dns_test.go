package config

import (
	"errors"
	"net"

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
				"cname.domain": {&dns.CNAME{Target: "custom.domain"}},
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
				ContainSubstring("cname.domain = "),
			))
		})
	})

	Describe("UnmarshalYAML", func() {
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

		It("Should return an error if a CNAME is accomanied by any other record", func() {
			c := CustomDNSEntries{}
			err := c.UnmarshalYAML(func(i interface{}) error {
				*i.(*string) = "CNAME(example.com),A(1.2.3.4)"

				return nil
			})
			Expect(err).Should(HaveOccurred())
			Expect(err).Should(MatchError("when a CNAME record is present, it must be the only record in the mapping"))
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
})
