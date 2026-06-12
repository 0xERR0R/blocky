package config

import (
	"github.com/creasty/defaults"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Ports.FreeBind", func() {
	It("defaults to false", func() {
		var ports Ports
		Expect(defaults.Set(&ports)).Should(Succeed())
		Expect(ports.FreeBind).Should(BeFalse())
	})
})

var _ = Describe("Ports.ProxyProtocol", func() {
	It("defaults to no PROXY protocol listeners", func() {
		var ports Ports
		Expect(defaults.Set(&ports)).Should(Succeed())
		Expect(ports.ProxyProtocol).Should(BeEmpty())
		Expect(ports.ProxyProtocol.Has(ProxyProtocolTypeDns)).Should(BeFalse())
	})

	It("reports the configured listener families via Has", func() {
		ports := Ports{ProxyProtocol: ProxyProtocolListeners{ProxyProtocolTypeHttps, ProxyProtocolTypeTls}}
		Expect(ports.ProxyProtocol.Has(ProxyProtocolTypeHttps)).Should(BeTrue())
		Expect(ports.ProxyProtocol.Has(ProxyProtocolTypeTls)).Should(BeTrue())
		Expect(ports.ProxyProtocol.Has(ProxyProtocolTypeDns)).Should(BeFalse())
		Expect(ports.ProxyProtocol.Has(ProxyProtocolTypeHttp)).Should(BeFalse())
	})

	It("rejects duplicate listener families", func() {
		ports := Ports{
			DOHPath: "/dns-query",
			ProxyProtocol: ProxyProtocolListeners{
				ProxyProtocolTypeHttps,
				ProxyProtocolTypeHttps,
			},
		}

		Expect(ports.validate()).Should(MatchError(ContainSubstring(
			`ports.proxyProtocol contains duplicate listener family "https"`)))
	})

	It("rejects listener families without a configured port", func() {
		ports := Ports{
			DOHPath:       "/dns-query",
			ProxyProtocol: ProxyProtocolListeners{ProxyProtocolTypeTls},
		}

		Expect(ports.validate()).Should(MatchError(ContainSubstring(
			`ports.proxyProtocol includes "tls" but ports.tls is empty`)))
	})
})

var _ = Describe("Ports.PrivilegedPorts", func() {
	It("returns privileged listen entries across DNS, HTTP, HTTPS and TLS", func() {
		ports := Ports{
			DNS:   ListenConfig{":53"},
			HTTP:  ListenConfig{":4000"},
			HTTPS: ListenConfig{"127.0.0.1:443"},
			TLS:   ListenConfig{"[::1]:853"},
		}

		Expect(ports.PrivilegedPorts()).Should(ConsistOf(":53", "127.0.0.1:443", "[::1]:853"))
	})

	It("returns empty when every configured port is unprivileged", func() {
		ports := Ports{DNS: ListenConfig{":1053"}, HTTP: ListenConfig{":4000"}}

		Expect(ports.PrivilegedPorts()).Should(BeEmpty())
	})

	It("treats port 1023 as privileged and 1024 as unprivileged", func() {
		ports := Ports{DNS: ListenConfig{":1023"}, HTTP: ListenConfig{":1024"}}

		Expect(ports.PrivilegedPorts()).Should(ConsistOf(":1023"))
	})

	It("handles a bare port without a colon (robustness; prefixPorts normalises these during unmarshal)", func() {
		ports := Ports{DNS: ListenConfig{"53"}}

		Expect(ports.PrivilegedPorts()).Should(ConsistOf("53"))
	})

	It("ignores empty and unparseable entries", func() {
		ports := Ports{DNS: ListenConfig{"", "notaport"}}

		Expect(ports.PrivilegedPorts()).Should(BeEmpty())
	})

	It("does not treat port 0 (OS-assigned ephemeral) as privileged", func() {
		ports := Ports{DNS: ListenConfig{":0"}, HTTP: ListenConfig{"127.0.0.1:0"}}

		Expect(ports.PrivilegedPorts()).Should(BeEmpty())
	})
})

var _ = Describe("extractPort", func() {
	DescribeTable("parses the port from a listen address",
		func(addr string, expectedPort uint16, expectedOK bool) {
			port, ok := extractPort(addr)
			Expect(ok).Should(Equal(expectedOK))
			if expectedOK {
				Expect(port).Should(Equal(expectedPort))
			}
		},
		Entry("bare port", "53", uint16(53), true),
		Entry("colon-prefixed", ":53", uint16(53), true),
		Entry("ipv4 host", "127.0.0.1:53", uint16(53), true),
		Entry("ipv6 host", "[::1]:853", uint16(853), true),
		Entry("hostname high port", "localhost:5353", uint16(5353), true),
		Entry("empty string", "", uint16(0), false),
		Entry("non-numeric", "notaport", uint16(0), false),
	)
})
