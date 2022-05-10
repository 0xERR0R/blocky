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
		mInner    *MockResolver
		mNext     *MockResolver

		fqdnOriginal  string
		fqdnRewritten string

		mNextResponse *model.Response
	)

	BeforeEach(func() {
		mInner = &MockResolver{}
		mNext = &MockResolver{}

		sutConfig = config.RewriteConfig{Rewrite: map[string]string{"original": "rewritten"}}
	})

	JustBeforeEach(func() {
		sut = NewRewriterResolver(sutConfig, mInner)
		sut.Next(mNext)
	})

	AfterEach(func() {
		mInner.AssertExpectations(GinkgoT())
		mNext.AssertExpectations(GinkgoT())
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
		var request *model.Request

		AfterEach(func() {
			request = newRequest(fqdnOriginal, dns.Type(dns.TypeA))

			mInner.On("Resolve", mock.Anything)
			mInner.ResponseFn = func(req *dns.Msg) *dns.Msg {
				Expect(req).Should(Equal(request.Req))

				// Inner should see fqdnRewritten
				q := req.Question[0]
				Expect(q.Name).Should(Equal(fqdnRewritten))

				res := new(dns.Msg)
				res.SetReply(req)

				ptr := new(dns.PTR)
				ptr.Ptr = fqdnRewritten
				ptr.Hdr = util.CreateHeader(q, 1)
				res.Answer = append(res.Answer, ptr)

				return res
			}

			resp, err := sut.Resolve(request)
			Expect(err).Should(Succeed())
			if resp != mNextResponse {
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
			mInner.ResolveFn = func(req *model.Request) (*model.Response, error) {
				Expect(req).Should(Equal(request))

				// Inner should see fqdnRewritten
				Expect(req.Req.Question[0].Name).Should(Equal(fqdnRewritten))

				return mInner.next.Resolve(req)
			}

			// Resolver after RewriterResolver should see `fqdnOriginal`
			mNext.On("Resolve", mock.Anything)
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
				Expect(len(c)).Should(BeNumerically(">", len(innerOutput)))
			})
		})
	})
})
