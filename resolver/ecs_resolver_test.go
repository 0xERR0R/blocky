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

			It("should add Ecs information with subnet 32", func() {
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

			It("should add Ecs information with subnet 24", func() {
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
