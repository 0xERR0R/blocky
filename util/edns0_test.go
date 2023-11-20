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
		When("OPT record is present", func() {
			BeforeEach(func() {
				opt := new(dns.OPT)
				opt.Hdr.Name = "."
				opt.Hdr.Rrtype = dns.TypeOPT
				baseMsg.Extra = append(baseMsg.Extra, opt)
			})

			It("should remove it", func() {
				Expect(RemoveEdns0Record(baseMsg)).Should(BeTrue())

				Expect(baseMsg.IsEdns0()).Should(BeNil())
			})
		})

		When("OPT record is not present", func() {
			It("should do nothing ", func() {
				Expect(RemoveEdns0Record(baseMsg)).Should(BeFalse())
			})
		})

		When("Extra is nil", func() {
			BeforeEach(func() {
				baseMsg.Extra = nil
			})

			It("should do nothing", func() {
				Expect(RemoveEdns0Record(baseMsg)).Should(BeFalse())
			})
		})

		When("message is nil", func() {
			It("should do nothing", func() {
				Expect(RemoveEdns0Record(nil)).Should(BeFalse())
			})
		})
	})

	Describe("GetEdns0Option", func() {
		When("Option is present", func() {
			var eso *dns.EDNS0_SUBNET

			BeforeEach(func() {
				opt := new(dns.OPT)
				opt.Hdr.Name = "."
				opt.Hdr.Rrtype = dns.TypeOPT
				eso = new(dns.EDNS0_SUBNET)
				eso.Code = dns.EDNS0SUBNET
				eso.Address = net.ParseIP("192.168.0.0")
				eso.Family = 1
				eso.SourceNetmask = 24
				opt.Option = append(opt.Option, eso)
				baseMsg.Extra = append(baseMsg.Extra, opt)
			})

			It("should return it", func() {
				Expect(GetEdns0Option[*dns.EDNS0_SUBNET](baseMsg)).Should(Equal(eso))
			})
		})

		When("Option is not present", func() {
			BeforeEach(func() {
				opt := new(dns.OPT)
				opt.Hdr.Name = "."
				opt.Hdr.Rrtype = dns.TypeOPT
				opt.Option = append(opt.Option, new(dns.EDNS0_EDE))
				baseMsg.Extra = append(baseMsg.Extra, opt)
			})

			It("should return nil", func() {
				Expect(GetEdns0Option[*dns.EDNS0_SUBNET](baseMsg)).Should(BeNil())
			})
		})

		When("Extra is nil", func() {
			BeforeEach(func() {
				baseMsg.Extra = nil
			})

			It("should return nil", func() {
				Expect(GetEdns0Option[*dns.EDNS0_SUBNET](baseMsg)).Should(BeNil())
			})
		})

		When("message is nil", func() {
			It("should return nil", func() {
				Expect(GetEdns0Option[*dns.EDNS0_SUBNET](nil)).Should(BeNil())
			})
		})
	})

	Describe("RemoveEdns0Option", func() {
		When("Option is present", func() {
			BeforeEach(func() {
				opt := new(dns.OPT)
				opt.Hdr.Name = "."
				opt.Hdr.Rrtype = dns.TypeOPT
				eso := new(dns.EDNS0_SUBNET)
				eso.Code = dns.EDNS0SUBNET
				opt.Option = append(opt.Option, eso)
				baseMsg.Extra = append(baseMsg.Extra, opt)
			})

			It("should remove it", func() {
				Expect(RemoveEdns0Option[*dns.EDNS0_SUBNET](baseMsg)).Should(BeTrue())

				Expect(baseMsg).ShouldNot(HaveEdnsOption(dns.EDNS0SUBNET))
			})
		})

		When("Option is not present", func() {
			BeforeEach(func() {
				opt := new(dns.OPT)
				opt.Hdr.Name = "."
				opt.Hdr.Rrtype = dns.TypeOPT
				opt.Option = append(opt.Option, new(dns.EDNS0_EDE))
				baseMsg.Extra = append(baseMsg.Extra, opt)
			})
			It("should return false", func() {
				Expect(RemoveEdns0Option[*dns.EDNS0_SUBNET](baseMsg)).Should(BeFalse())
			})
		})

		When("Extra is nil", func() {
			BeforeEach(func() {
				baseMsg.Extra = nil
			})

			It("should return false", func() {
				Expect(RemoveEdns0Option[*dns.EDNS0_SUBNET](baseMsg)).Should(BeFalse())
			})
		})

		When("message is nil", func() {
			It("should return false", func() {
				Expect(RemoveEdns0Option[*dns.EDNS0_SUBNET](nil)).Should(BeFalse())
			})
		})
	})

	Describe("SetEdns0Option", func() {
		When("Option is not present", func() {
			var eso *dns.EDNS0_SUBNET

			BeforeEach(func() {
				Expect(baseMsg).ShouldNot(HaveEdnsOption(dns.EDNS0SUBNET))
				Expect(SetEdns0Option(baseMsg, new(dns.EDNS0_EDE))).Should(BeTrue())

				eso = new(dns.EDNS0_SUBNET)
				eso.Code = dns.EDNS0SUBNET
			})

			It("should add the option", func() {
				Expect(SetEdns0Option(baseMsg, eso)).Should(BeTrue())

				Expect(baseMsg).Should(HaveEdnsOption(dns.EDNS0SUBNET))
			})
		})

		When("Option is present", func() {
			var (
				eso  *dns.EDNS0_SUBNET
				eso2 *dns.EDNS0_SUBNET
			)

			BeforeEach(func() {
				eso = new(dns.EDNS0_SUBNET)
				eso.Code = dns.EDNS0SUBNET
				eso.Address = net.ParseIP("1.1.1.1")
				eso.Family = 1
				eso.SourceNetmask = 32

				eso2 = new(dns.EDNS0_SUBNET)
				eso2.Code = dns.EDNS0SUBNET
				eso2.Address = net.ParseIP("2.2.2.2")
				eso2.Family = 1
				eso2.SourceNetmask = 32

				Expect(SetEdns0Option(baseMsg, eso)).Should(BeTrue())
			})

			It("should replace it", func() {
				Expect(GetEdns0Option[*dns.EDNS0_SUBNET](baseMsg)).Should(Equal(eso))
				Expect(SetEdns0Option(baseMsg, eso2)).Should(BeTrue())
				Expect(GetEdns0Option[*dns.EDNS0_SUBNET](baseMsg)).Should(Equal(eso2))
			})
		})

		When("message is nil", func() {
			It("should return false", func() {
				Expect(SetEdns0Option(nil, new(dns.EDNS0_SUBNET))).Should(BeFalse())
			})
		})

		When("option is nil", func() {
			It("should do nothing if option is nil", func() {
				Expect(SetEdns0Option(baseMsg, nil)).Should(BeFalse())
			})
		})
	})
})
