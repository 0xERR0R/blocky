package util

import (
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	exampleDomain = "example.com"
	testTxt       = "test"
)

var _ = Describe("EDNS0 utils", func() {
	var baseMsg *dns.Msg

	BeforeEach(func() {
		baseMsg = new(dns.Msg)
		txt := new(dns.TXT)
		txt.Hdr.Name = exampleDomain + "."
		txt.Hdr.Rrtype = dns.TypeTXT
		txt.Txt = []string{testTxt}
		baseMsg.Extra = append(baseMsg.Extra, txt)
	})

	Describe("RemoveEdns0Record", func() {
		It("should remove OPT record", func() {
			opt := new(dns.OPT)
			opt.Hdr.Name = "."
			opt.Hdr.Rrtype = dns.TypeOPT
			baseMsg.Extra = append(baseMsg.Extra, opt)

			RemoveEdns0Record(baseMsg)

			Expect(baseMsg.IsEdns0()).Should(BeNil())
		})

		It("should do nothing if OPT record is not present", func() {
			Expect(func() {
				RemoveEdns0Record(baseMsg)
			}).NotTo(Panic())
		})

		It("should do nothing if message is nil", func() {
			Expect(func() {
				RemoveEdns0Record(nil)
			}).NotTo(Panic())
		})
	})

	Describe("GetEdns0Record", func() {
		It("should return OPT record if present", func() {
			baseOpt := new(dns.OPT)
			baseOpt.Hdr.Name = "."
			baseOpt.Hdr.Rrtype = dns.TypeOPT
			baseMsg.Extra = append(baseMsg.Extra, baseOpt)

			opt := GetEdns0Record(baseMsg)

			Expect(opt).Should(Equal(baseOpt))
		})

		It("should return OPT record if not present", func() {
			opt := GetEdns0Record(baseMsg)

			Expect(opt).ShouldNot(BeNil())
			Expect(opt.Hdr.Name).Should(Equal("."))
			Expect(opt.Hdr.Rrtype).Should(Equal(dns.TypeOPT))
		})

		It("should add OPT record if not present", func() {
			baseMsg.Extra = nil

			opt := GetEdns0Record(baseMsg)

			Expect(opt).ShouldNot(BeNil())
			Expect(opt.Hdr.Name).Should(Equal("."))
			Expect(opt.Hdr.Rrtype).Should(Equal(dns.TypeOPT))
		})

		It("should do nothing if message is nil", func() {
			Expect(func() {
				GetEdns0Record(nil)
			}).NotTo(Panic())
		})
	})

	Describe("HasEdns0Option", func() {
		It("should return true if option is present", func() {
			opt := new(dns.OPT)
			opt.Hdr.Name = "."
			opt.Hdr.Rrtype = dns.TypeOPT
			opt.Option = append(opt.Option, new(dns.EDNS0_SUBNET))
			baseMsg.Extra = append(baseMsg.Extra, opt)

			Expect(HasEdns0Option(baseMsg, dns.EDNS0SUBNET)).Should(BeTrue())
		})

		It("should return false if option is not present", func() {
			opt := new(dns.OPT)
			opt.Hdr.Name = "."
			opt.Hdr.Rrtype = dns.TypeOPT
			opt.Option = append(opt.Option, new(dns.EDNS0_EDE))
			baseMsg.Extra = append(baseMsg.Extra, opt)
			Expect(HasEdns0Option(baseMsg, dns.EDNS0SUBNET)).Should(BeFalse())
		})

		It("should return false if OPT record is not present", func() {
			Expect(HasEdns0Option(baseMsg, dns.EDNS0SUBNET)).Should(BeFalse())
		})

		It("should do nothing if message is nil", func() {
			Expect(HasEdns0Option(nil, dns.EDNS0SUBNET)).Should(BeFalse())
		})
	})
})
