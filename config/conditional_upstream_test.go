package config

import (
	"errors"

	"github.com/creasty/defaults"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ConditionalUpstreamConfig", func() {
	var cfg ConditionalUpstream

	suiteBeforeEach()

	BeforeEach(func() {
		cfg = ConditionalUpstream{
			Mapping: ConditionalUpstreamMapping{
				Upstreams: map[string][]Upstream{
					"fritz.box": {Upstream{Net: NetProtocolTcpUdp, Host: "fbTest"}},
					"other.box": {Upstream{Net: NetProtocolTcpUdp, Host: "otherTest"}},
					".":         {Upstream{Net: NetProtocolTcpUdp, Host: "dotTest"}},
				},
			},
		}
	})

	Describe("IsEnabled", func() {
		It("should be false by default", func() {
			cfg := ConditionalUpstream{}
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
				cfg := ConditionalUpstream{
					Mapping: ConditionalUpstreamMapping{Upstreams: map[string][]Upstream{}},
				}

				Expect(cfg.IsEnabled()).Should(BeFalse())
			})
		})
	})

	Describe("LogConfig", func() {
		It("should log configuration", func() {
			cfg.LogConfig(logger)

			Expect(hook.Calls).ShouldNot(BeEmpty())
			Expect(hook.Messages).Should(ContainElement(ContainSubstring("fritz.box = ")))
		})
	})

	Describe("UnmarshalYAML", func() {
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
				Net: NetProtocolTcpUdp, Host: "1.2.3.4", Port: 53,
			}))
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
})
