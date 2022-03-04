package resolver

import (
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("RewriterResolver", func() {
	var (
		sut       ChainedResolver
		sutConfig config.RewriteConfig
		mInner    *resolverMock
		mNext     *MockResolver

		fqdnOriginal  string
		fqdnRewritten string

		request  *model.Request
		response model.Response
		mNextResponse *model.Response
	)

	BeforeEach(func() {
		mInner = &resolverMock{}
		mNext = &MockResolver{}

		sutConfig = config.RewriteConfig{Rewrite: map[string]string{"original": "rewritten"}}
	})

	JustBeforeEach(func() {
		sut = NewRewriterResolver(sutConfig, mInner)
		sut.Next(mNext)
	})

	When("has no configuration", func() {
		BeforeEach(func() {
			sutConfig = config.RewriteConfig{}
		})

		It("should return the inner resolver", func() {
			Expect(sut).Should(BeIdenticalTo(mInner))
		})
	})

	When("has rewrite", func() {
		AfterEach(func() {
			request = newRequest(fqdnOriginal, dns.TypeA)

			mInner.On("Resolve", mock.Anything).Return(&response, nil).Run(func(args mock.Arguments) {
				Expect(args.Get(0)).Should(Equal(request))

				q := request.Req.Question[0]
				Expect(q.Name).Should(Equal(fqdnRewritten))

				res := new(dns.Msg)
				res.SetReply(request.Req)

				ptr := new(dns.PTR)
				ptr.Ptr = fqdnRewritten
				ptr.Hdr = util.CreateHeader(q, 1)
				res.Answer = append(res.Answer, ptr)

				response = model.Response{Res: res}
			})

			resp, err := sut.Resolve(request)
			Expect(err).Should(Succeed())
			if resp != mNextResponse {
				Expect(resp).Should(Equal(&response))
				Expect(resp.Res.Question[0].Name).Should(Equal(fqdnOriginal))
				Expect(resp.Res.Answer[0].Header().Name).Should(Equal(fqdnOriginal))
			}
		})

		It("should modify names", func() {
			fqdnOriginal = "test.original."
			fqdnRewritten = "test.rewritten."
		})

		It("should modify subdomains", func() {
			fqdnOriginal = "sub.test.original."
			fqdnRewritten = "sub.test.rewritten."
		})

		It("should not modify unknown names", func() {
			fqdnOriginal = "test.untouched."
			fqdnRewritten = fqdnOriginal
		})

		It("should not modify name if subdomain", func() {
			fqdnOriginal = "test.original.untouched."
			fqdnRewritten = fqdnOriginal
		})

		It("should call next resolver", func() {
			fqdnOriginal = "test.original."
			fqdnRewritten = "test.rewritten."

			// Make inner call the NoOpResolver
			mInner := MockResolver{ResolveFn: NewNoOpResolver().Resolve}

			sut = NewRewriterResolver(sutConfig, &mInner)
			sut.Next(mNext)

			// Resolver after RewriterResolver should see `fqdnOriginal`
			mNext.ResolveFn = func(req *model.Request) (*model.Response, error) {
				Expect(req.Req.Question[0].Name).Should(Equal(fqdnOriginal))
				return mNextResponse, nil
			}
		})
	})

	Describe("Configuration output", func() {
		When("resolver is enabled", func() {
			It("should return configuration", func() {
				innerOutput := []string{"inner:", "config-output"}
				mInner.On("Configuration").Return(innerOutput)

				c := sut.Configuration()
				m.AssertExpectations(GinkgoT())
				Expect(len(c)).Should(BeNumerically(">", len(innerOutput)))
			})
		})
	})
})
