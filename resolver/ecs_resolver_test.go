package resolver

import (
	"net"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/util"
	"github.com/creasty/defaults"

	. "github.com/0xERR0R/blocky/helpertest"
	. "github.com/0xERR0R/blocky/model"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("EcsResolver", func() {
	var (
		sut        *EcsResolver
		sutConfig  config.EcsConfig
		m          *mockResolver
		mockAnswer *dns.Msg
		err        error
		origIP     net.IP
		ecsIP      net.IP
	)

	Describe("Type", func() {
		It("follows conventions", func() {
			expectValidResolverType(sut)
		})
	})

	BeforeEach(func() {
		err = defaults.Set(&sutConfig)
		Expect(err).ShouldNot(HaveOccurred())

		mockAnswer = new(dns.Msg)
		origIP = net.ParseIP("1.2.3.4")
		ecsIP = net.ParseIP("4.3.2.1")
	})

	JustBeforeEach(func() {
		if m == nil {
			m = &mockResolver{}
			m.On("Resolve", mock.Anything).Return(&Response{
				Res:    mockAnswer,
				RType:  ResponseTypeCUSTOMDNS,
				Reason: "Test",
			}, nil)
		}

		sut = NewEcsResolver(sutConfig).(*EcsResolver)
		sut.Next(m)
	})

	When("ecs is disabled", func() {
		Describe("IsEnabled", func() {
			It("is false", func() {
				Expect(sut.IsEnabled()).Should(BeFalse())
			})
		})
	})

	When("ecs is enabled", func() {
		BeforeEach(func() {
			sutConfig.UseEcsAsClient = true
		})

		Describe("IsEnabled", func() {
			It("is true", func() {
				Expect(sut.IsEnabled()).Should(BeTrue())
			})
		})

		When("use ecs client ip is enabled", func() {
			BeforeEach(func() {
				sutConfig.UseEcsAsClient = true
			})

			It("should change ClientIP with subnet 32", func() {
				request := newRequest("example.com.", A)
				request.ClientIP = origIP

				addEcsOption(request.Req, ecsIP, ecsIpv4Mask)

				m.ResolveFn = func(req *Request) (*Response, error) {
					Expect(req.ClientIP).Should(Equal(ecsIP))

					return respondWith(mockAnswer), nil
				}

				Expect(sut.Resolve(request)).
					Should(
						SatisfyAll(
							HaveNoAnswer(),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
							HaveReason("Test")))
			})

			It("shouldn't change ClientIP with subnet 24", func() {
				request := newRequest("example.com.", A)
				request.ClientIP = origIP

				addEcsOption(request.Req, ecsIP, 24)

				m.ResolveFn = func(req *Request) (*Response, error) {
					Expect(req.ClientIP).Should(Equal(origIP))

					return respondWith(mockAnswer), nil
				}

				Expect(sut.Resolve(request)).
					Should(
						SatisfyAll(
							HaveNoAnswer(),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
							HaveReason("Test")))
			})
		})

		When("forward ecs is enabled", func() {
			BeforeEach(func() {
				sutConfig.ForwardEcs = true
				sutConfig.IPv4Mask = 32
				sutConfig.IPv6Mask = 128
			})

			It("should add Ecs information with subnet 32", func() {
				request := newRequest("example.com.", A)
				request.ClientIP = origIP

				m.ResolveFn = func(req *Request) (*Response, error) {
					Expect(req.ClientIP).Should(Equal(origIP))
					Expect(req.Req).Should(HaveEdnsOption(dns.EDNS0SUBNET))

					return respondWith(mockAnswer), nil
				}

				Expect(sut.Resolve(request)).
					Should(
						SatisfyAll(
							HaveNoAnswer(),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
							HaveReason("Test")))
			})

			It("should add Ecs information with subnet 128", func() {
				request := newRequest("example.com.", AAAA)
				request.ClientIP = net.ParseIP("2001:db8::68")

				m.ResolveFn = func(req *Request) (*Response, error) {
					Expect(req.Req).Should(HaveEdnsOption(dns.EDNS0SUBNET))

					return respondWith(mockAnswer), nil
				}

				Expect(sut.Resolve(request)).
					Should(
						SatisfyAll(
							HaveNoAnswer(),
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
							HaveReason("Test")))
			})
		})
	})

	Describe("getMask", func() {
		When("ECSv4Mask", func() {
			It("should return 32 when input is 32", func() {
				Expect(getMask(ecsIpv4Mask, ecsIpv4Mask)).Should(Equal(ecsIpv4Mask))
			})

			It("should return 0 when input is 33", func() {
				Expect(getMask(ecsIpv4Mask+1, ecsIpv4Mask)).Should(Equal(uint8(0)))
			})
		})

		When("ECSv6Mask", func() {
			It("should return 128 when input is 128", func() {
				Expect(getMask(ecsIpv6Mask, ecsIpv6Mask)).Should(Equal(ecsIpv6Mask))
			})

			It("should return 0 when input is 129", func() {
				Expect(getMask(ecsIpv6Mask+1, ecsIpv6Mask)).Should(Equal(uint8(0)))
			})
		})
	})
})

// addEcsOption adds the subnet information to the request as EDNS0 option
func addEcsOption(req *dns.Msg, ip net.IP, netmask uint8) {
	e := new(dns.EDNS0_SUBNET)
	e.Code = dns.EDNS0SUBNET
	e.SourceScope = ecsSourceScope
	e.Family = ecsIpv4Family
	e.SourceNetmask = netmask
	e.Address = ip
	util.SetEdns0Option(req, e)
}

// respondWith creates a new Response with the given request and message
func respondWith(res *dns.Msg) *Response {
	return &Response{Res: res, RType: ResponseTypeRESOLVED, Reason: "Test"}
}
