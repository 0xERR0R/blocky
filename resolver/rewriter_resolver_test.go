package resolver

import (
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/sirupsen/logrus"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

const (
	sampleOriginal  = "test.original."
	sampleRewritten = "test.rewritten."
)

var _ = Describe("RewriterResolver", func() {
	var (
		sut       ChainedResolver
		sutConfig config.RewriterConfig
		mInner    *mockResolver
		mNext     *mockResolver

		fqdnOriginal  string
		fqdnRewritten string

		mNextResponse *model.Response
	)

	Describe("Type", func() {
		It("follows conventions", func() {
			expectValidResolverType(sut)
		})
	})

	BeforeEach(func() {
		mInner = &mockResolver{}
		mNext = &mockResolver{}

		sutConfig = config.RewriterConfig{Rewrite: map[string]string{"original": "rewritten"}}
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
			sutConfig = config.RewriterConfig{}
		})

		It("should return the inner resolver", func() {
			Expect(sut).Should(BeIdenticalTo(mInner))
		})
	})

	When("has rewrite", func() {
		var request *model.Request
		var expectNilAnswer bool

		BeforeEach(func() {
			expectNilAnswer = false
		})

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
				if expectNilAnswer {
					Expect(resp.Res.Answer).Should(BeEmpty())
				} else {
					Expect(resp.Res.Answer[0].Header().Name).Should(Equal(fqdnOriginal))
				}
			}
		})

		It("should modify names", func() {
			fqdnOriginal = sampleOriginal
			fqdnRewritten = sampleRewritten
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
			fqdnOriginal = sampleOriginal
			fqdnRewritten = sampleRewritten
			expectNilAnswer = true

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

		It("should not call next resolver", func() {
			fqdnOriginal = sampleOriginal
			fqdnRewritten = sampleRewritten
			expectNilAnswer = true

			// Make inner return a nil Answer but not an empty Response
			mInner.ResolveFn = func(req *model.Request) (*model.Response, error) {
				Expect(req).Should(Equal(request))

				// Inner should see fqdnRewritten
				Expect(req.Req.Question[0].Name).Should(Equal(fqdnRewritten))

				return &model.Response{Res: &dns.Msg{Question: req.Req.Question, Answer: nil}}, nil
			}

			// Resolver after RewriterResolver should not be called `fqdnOriginal`
			mNext.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
		})

		When("has fallbackUpstream", func() {
			BeforeEach(func() {
				sutConfig.FallbackUpstream = true
			})

			It("should call next resolver", func() {
				fqdnOriginal = sampleOriginal
				fqdnRewritten = sampleRewritten

				// Make inner return a nil Answer but not an empty Response
				mInner.ResolveFn = func(req *model.Request) (*model.Response, error) {
					Expect(req).Should(Equal(request))

					// Inner should see fqdnRewritten
					Expect(req.Req.Question[0].Name).Should(Equal(fqdnRewritten))

					return &model.Response{Res: &dns.Msg{Question: req.Req.Question, Answer: nil}}, nil
				}

				// Resolver after RewriterResolver should see `fqdnOriginal`
				mNext.On("Resolve", mock.Anything)
				mNext.ResolveFn = func(req *model.Request) (*model.Response, error) {
					Expect(req.Req.Question[0].Name).Should(Equal(fqdnOriginal))

					return mNextResponse, nil
				}
			})
		})
	})

	Describe("Configuration output", func() {
		When("resolver is enabled", func() {
			It("should return configuration", func() {
				mInner.On("LogConfig")
				mInner.On("IsEnabled").Return(true)

				sut.LogConfig(logrus.NewEntry(log.Log()))
			})
		})
	})
})
