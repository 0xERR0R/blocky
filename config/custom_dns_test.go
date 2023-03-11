package config

import (
	"errors"
	"net"

	"github.com/creasty/defaults"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("CustomDNSConfig", func() {
	var (
		cfg CustomDNSConfig
	)

	suiteBeforeEach()

	BeforeEach(func() {
		cfg = CustomDNSConfig{
			Mapping: CustomDNSMapping{
				HostIPs: map[string][]net.IP{
					"custom.domain": {net.ParseIP("192.168.143.123")},
					"ip6.domain":    {net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334")},
					"multiple.ips": {
						net.ParseIP("192.168.143.123"),
						net.ParseIP("192.168.143.125"),
						net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
					},
				},
			},
		}
	})

	Describe("IsEnabled", func() {
		It("should be false by default", func() {
			cfg := CustomDNSConfig{}
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
				cfg := CustomDNSConfig{}

				Expect(cfg.IsEnabled()).Should(BeFalse())
			})
		})
	})

	Describe("LogConfig", func() {
		It("should log configuration", func() {
			cfg.LogConfig(logger)

			Expect(hook.Calls).ShouldNot(BeEmpty())
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("custom.domain = ")))
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("multiple.ips = ")))
		})
	})

	Describe("UnmarshalYAML", func() {
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
})
