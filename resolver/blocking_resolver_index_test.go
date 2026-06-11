package resolver

import (
	"net"

	"github.com/0xERR0R/blocky/config"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("clientGroupsIndex", func() {
	var idx clientGroupsIndex

	BeforeEach(func() {
		cfg := config.Blocking{
			ClientGroupsBlock: map[string][]string{
				"default":          {"gr1"},
				"10.0.0.0/8":       {"gr1"},
				"192.168.178.55":   {"gr2"},
				"Laptop":           {"gr1"},
				"phone,tablet":     {"gr2"},
				"host.Example.com": {"gr1"},
			},
		}

		idx = newClientGroupsIndex(cfg)
	})

	It("keeps every identifier (lowercased, comma-split) in byID for exact lookups", func() {
		Expect(idx.byID).Should(HaveKey("default"))
		Expect(idx.byID).Should(HaveKey("10.0.0.0/8"))
		Expect(idx.byID).Should(HaveKey("192.168.178.55"))
		Expect(idx.byID).Should(HaveKey("laptop"))
		Expect(idx.byID).Should(HaveKey("phone"))
		Expect(idx.byID).Should(HaveKey("tablet"))
		Expect(idx.byID).Should(HaveKey("host.example.com"))
	})

	It("pre-parses only the CIDR identifiers into ready-to-use networks", func() {
		Expect(idx.cidrs).Should(HaveLen(1))
		Expect(idx.cidrs[0].ipNet).ShouldNot(BeNil())
		Expect(idx.cidrs[0].ipNet.Contains(net.ParseIP("10.1.2.3"))).Should(BeTrue())
		Expect(idx.cidrs[0].ipNet.Contains(net.ParseIP("11.0.0.1"))).Should(BeFalse())
	})

	It("classifies every dotted identifier as an FQDN candidate (faithful to isFQDN)", func() {
		ids := make([]string, 0, len(idx.fqdns))
		for _, f := range idx.fqdns {
			ids = append(ids, f.identifier)
		}

		Expect(ids).Should(ConsistOf("10.0.0.0/8", "192.168.178.55", "host.example.com"))
	})
})
