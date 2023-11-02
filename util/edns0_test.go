package util

import (
	"net"

	. "github.com/0xERR0R/blocky/helpertest"
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

	Describe("GetEdns0Option", func() {
		It("should return option if present", func() {
			opt := new(dns.OPT)
			opt.Hdr.Name = "."
			opt.Hdr.Rrtype = dns.TypeOPT
			eso := new(dns.EDNS0_SUBNET)
			eso.Code = dns.EDNS0SUBNET
			opt.Option = append(opt.Option, eso)
			baseMsg.Extra = append(baseMsg.Extra, opt)

			Expect(GetEdns0Option(baseMsg, dns.EDNS0SUBNET)).Should(Equal(eso))
		})

		It("should return nil if option is not present", func() {
			opt := new(dns.OPT)
			opt.Hdr.Name = "."
			opt.Hdr.Rrtype = dns.TypeOPT
			opt.Option = append(opt.Option, new(dns.EDNS0_EDE))
			baseMsg.Extra = append(baseMsg.Extra, opt)
			Expect(GetEdns0Option(baseMsg, dns.EDNS0SUBNET)).Should(BeNil())
		})

		It("should return nil if OPT record is not present", func() {
			Expect(GetEdns0Option(baseMsg, dns.EDNS0SUBNET)).Should(BeNil())
		})

		It("should do nothing if message is nil", func() {
			Expect(GetEdns0Option(nil, dns.EDNS0SUBNET)).Should(BeNil())
		})
	})

	Describe("RemoveEdns0Option", func() {
		It("should remove option if present", func() {
			opt := new(dns.OPT)
			opt.Hdr.Name = "."
			opt.Hdr.Rrtype = dns.TypeOPT
			eso := new(dns.EDNS0_SUBNET)
			eso.Code = dns.EDNS0SUBNET
			opt.Option = append(opt.Option, eso)
			baseMsg.Extra = append(baseMsg.Extra, opt)

			RemoveEdns0Option(baseMsg, dns.EDNS0SUBNET)

			Expect(baseMsg).ShouldNot(HaveEdnsOption(dns.EDNS0SUBNET))
		})

		It("should do nothing if option is not present", func() {
			opt := new(dns.OPT)
			opt.Hdr.Name = "."
			opt.Hdr.Rrtype = dns.TypeOPT
			opt.Option = append(opt.Option, new(dns.EDNS0_EDE))
			baseMsg.Extra = append(baseMsg.Extra, opt)
			Expect(func() {
				RemoveEdns0Option(baseMsg, dns.EDNS0SUBNET)
			}).NotTo(Panic())
		})

		It("should do nothing if OPT record is not present", func() {
			Expect(func() {
				RemoveEdns0Option(baseMsg, dns.EDNS0SUBNET)
			}).NotTo(Panic())
		})

		It("should do nothing if message is nil", func() {
			Expect(func() {
				RemoveEdns0Option(nil, dns.EDNS0SUBNET)
			}).NotTo(Panic())
		})
	})

	Describe("SetEdns0Option", func() {
		It("should add option if not present", func() {
			eso := new(dns.EDNS0_SUBNET)
			eso.Code = dns.EDNS0SUBNET

			SetEdns0Option(baseMsg, eso)

			Expect(baseMsg).Should(HaveEdnsOption(dns.EDNS0SUBNET))
		})

		It("should replace option if present", func() {
			opt := new(dns.OPT)
			opt.Hdr.Name = "."
			opt.Hdr.Rrtype = dns.TypeOPT
			opt.Option = append(opt.Option, new(dns.EDNS0_EDE))
			eso := new(dns.EDNS0_SUBNET)
			eso.Code = dns.EDNS0SUBNET
			eso.Address = net.ParseIP("1.1.1.1")
			opt.Option = append(opt.Option, eso)
			baseMsg.Extra = append(baseMsg.Extra, opt)

			eso2 := new(dns.EDNS0_SUBNET)
			eso2.Code = dns.EDNS0SUBNET
			eso2.Address = net.ParseIP("2.2.2.2")

			SetEdns0Option(baseMsg, eso2)
			Expect(baseMsg).Should(HaveEdnsOption(dns.EDNS0SUBNET))
		})

		It("should do nothing if message is nil", func() {
			eso := new(dns.EDNS0_SUBNET)
			eso.Code = dns.EDNS0SUBNET

			Expect(func() {
				SetEdns0Option(nil, eso)
			}).NotTo(Panic())
		})

		It("should do nothing if option is nil", func() {
			Expect(func() {
				SetEdns0Option(baseMsg, nil)
			}).NotTo(Panic())
		})
	})
})
