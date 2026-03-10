package configstore

import (
	"path/filepath"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Convert", func() {
	var store *ConfigStore

	BeforeEach(func() {
		tmpDir := GinkgoT().TempDir()

		var err error
		store, err = Open(filepath.Join(tmpDir, "test.db"))
		Expect(err).Should(Succeed())
		DeferCleanup(store.Close)
	})

	Describe("BuildBlockingConfig", func() {
		It("should build config from DB state", func() {
			Expect(store.PutClientGroup(&ClientGroup{
				Name:    "default",
				Clients: StringList{"192.168.1.0/24"},
				Groups:  StringList{"ads", "malware"},
			})).Should(Succeed())

			Expect(store.CreateBlocklistSource(&BlocklistSource{
				GroupName: "ads", ListType: "deny", SourceType: "http",
				Source: "https://example.com/ads.txt", Enabled: BoolPtr(true),
			})).Should(Succeed())
			Expect(store.CreateBlocklistSource(&BlocklistSource{
				GroupName: "ads", ListType: "allow", SourceType: "file",
				Source: "/etc/blocky/whitelist.txt", Enabled: BoolPtr(true),
			})).Should(Succeed())
			// Disabled source should be excluded
			Expect(store.CreateBlocklistSource(&BlocklistSource{
				GroupName: "ads", ListType: "deny", SourceType: "http",
				Source: "https://disabled.com/list.txt", Enabled: BoolPtr(false),
			})).Should(Succeed())

			Expect(store.PutBlockSettings(&BlockSettings{
				BlockType: "NXDOMAIN", BlockTTL: "30m",
			})).Should(Succeed())

			base := config.Blocking{}
			result, err := store.BuildBlockingConfig(base)
			Expect(err).Should(Succeed())

			Expect(result.ClientGroupsBlock).Should(HaveKey("default"))
			Expect(result.ClientGroupsBlock["default"]).Should(ConsistOf("ads", "malware"))

			Expect(result.Denylists).Should(HaveKey("ads"))
			Expect(result.Denylists["ads"]).Should(HaveLen(1)) // disabled one excluded
			Expect(result.Denylists["ads"][0].Type).Should(Equal(config.BytesSourceTypeHttp))

			Expect(result.Allowlists).Should(HaveKey("ads"))
			Expect(result.Allowlists["ads"]).Should(HaveLen(1))
			Expect(result.Allowlists["ads"][0].Type).Should(Equal(config.BytesSourceTypeFile))

			Expect(result.BlockType).Should(Equal("NXDOMAIN"))
			Expect(time.Duration(result.BlockTTL)).Should(Equal(30 * time.Minute))
		})

		It("should preserve YAML-only fields", func() {
			base := config.Blocking{
				Loading: config.SourceLoading{
					Concurrency: 8,
				},
			}

			result, err := store.BuildBlockingConfig(base)
			Expect(err).Should(Succeed())
			Expect(result.Loading.Concurrency).Should(Equal(uint(8)))
		})
	})

	Describe("BuildCustomDNSConfig", func() {
		It("should build DNS mapping from DB entries", func() {
			Expect(store.CreateCustomDNSEntry(&CustomDNSEntry{
				Domain: "myhost.local", RecordType: "A", Value: "192.168.1.100",
				TTL: 3600, Enabled: BoolPtr(true),
			})).Should(Succeed())
			Expect(store.CreateCustomDNSEntry(&CustomDNSEntry{
				Domain: "myhost.local", RecordType: "AAAA", Value: "fd00::1",
				TTL: 3600, Enabled: BoolPtr(true),
			})).Should(Succeed())
			// Disabled entry should be excluded
			Expect(store.CreateCustomDNSEntry(&CustomDNSEntry{
				Domain: "disabled.local", RecordType: "A", Value: "10.0.0.1",
				TTL: 3600, Enabled: BoolPtr(false),
			})).Should(Succeed())

			base := config.CustomDNS{CustomTTL: config.Duration(time.Hour)}
			result, err := store.BuildCustomDNSConfig(base)
			Expect(err).Should(Succeed())

			Expect(result.Mapping).Should(HaveLen(1))
			Expect(result.Mapping).Should(HaveKey("myhost.local."))

			rrs := result.Mapping["myhost.local."]
			Expect(rrs).Should(HaveLen(2))

			// Verify record types
			types := make([]uint16, len(rrs))
			for i, rr := range rrs {
				types[i] = rr.Header().Rrtype
			}
			Expect(types).Should(ContainElements(dns.TypeA, dns.TypeAAAA))

			// Preserved YAML-only field
			Expect(time.Duration(result.CustomTTL)).Should(Equal(time.Hour))
		})

		It("should handle CNAME records", func() {
			Expect(store.CreateCustomDNSEntry(&CustomDNSEntry{
				Domain: "alias.local", RecordType: "CNAME", Value: "real.local",
				TTL: 300, Enabled: BoolPtr(true),
			})).Should(Succeed())

			result, err := store.BuildCustomDNSConfig(config.CustomDNS{})
			Expect(err).Should(Succeed())

			rrs := result.Mapping["alias.local."]
			Expect(rrs).Should(HaveLen(1))

			cname, ok := rrs[0].(*dns.CNAME)
			Expect(ok).Should(BeTrue())
			Expect(cname.Target).Should(Equal("real.local."))
			Expect(cname.Hdr.Ttl).Should(Equal(uint32(300)))
		})

		It("should return empty mapping when no entries", func() {
			result, err := store.BuildCustomDNSConfig(config.CustomDNS{})
			Expect(err).Should(Succeed())
			Expect(result.Mapping).Should(BeEmpty())
		})
	})
})
