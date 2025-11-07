package dnssec

import (
	"context"
	"errors"

	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Query functions", func() {
	var (
		sut          *Validator
		trustStore   *TrustAnchorStore
		mockUpstream *mockResolver
		ctx          context.Context
	)

	BeforeEach(func(specCtx SpecContext) {
		ctx = specCtx

		var err error
		trustStore, err = NewTrustAnchorStore(nil)
		Expect(err).Should(Succeed())

		mockUpstream = &mockResolver{}
		logger, _ := log.NewMockEntry()

		sut = NewValidator(ctx, trustStore, logger, mockUpstream, 1, 10, 150, 30, 3600)
	})

	Describe("consumeQueryBudget", func() {
		It("should succeed with budget remaining", func() {
			ctx := context.WithValue(context.Background(), queryBudgetKey{}, 5)
			err := sut.consumeQueryBudget(ctx)
			Expect(err).Should(Succeed())
		})

		It("should fail when budget is exhausted", func() {
			ctx := context.WithValue(context.Background(), queryBudgetKey{}, 0)
			err := sut.consumeQueryBudget(ctx)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("budget exhausted"))
		})

		It("should fail when budget is negative", func() {
			ctx := context.WithValue(context.Background(), queryBudgetKey{}, -1)
			err := sut.consumeQueryBudget(ctx)
			Expect(err).Should(HaveOccurred())
		})

		It("should fail when budget is not initialized", func() {
			ctx := context.Background()
			err := sut.consumeQueryBudget(ctx)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("not initialized"))
		})
	})

	Describe("decrementQueryBudget", func() {
		It("should decrement budget by 1", func() {
			ctx := context.WithValue(context.Background(), queryBudgetKey{}, 5)
			newCtx := sut.decrementQueryBudget(ctx)

			budget := newCtx.Value(queryBudgetKey{}).(int)
			Expect(budget).Should(Equal(4))
		})

		It("should handle budget of 1", func() {
			ctx := context.WithValue(context.Background(), queryBudgetKey{}, 1)
			newCtx := sut.decrementQueryBudget(ctx)

			budget := newCtx.Value(queryBudgetKey{}).(int)
			Expect(budget).Should(Equal(0))
		})

		It("should return original context if budget not initialized", func() {
			ctx := context.Background()
			newCtx := sut.decrementQueryBudget(ctx)

			Expect(newCtx).Should(Equal(ctx))
		})

		It("should allow negative budget (no validation)", func() {
			ctx := context.WithValue(context.Background(), queryBudgetKey{}, 0)
			newCtx := sut.decrementQueryBudget(ctx)

			budget := newCtx.Value(queryBudgetKey{}).(int)
			Expect(budget).Should(Equal(-1))
		})
	})

	Describe("queryRecords", func() {
		It("should query upstream with DNSSEC enabled", func() {
			ctx := context.WithValue(context.Background(), queryBudgetKey{}, 10)

			expectedResponse := &dns.Msg{
				Answer: []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{
							Name:   "example.com.",
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						A: []byte{192, 0, 2, 1},
					},
				},
			}

			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				// Verify EDNS0 and DO bit are set
				Expect(req.Req.IsEdns0()).ShouldNot(BeNil())
				opt := req.Req.IsEdns0()
				Expect(opt.Do()).Should(BeTrue())

				// Verify question
				Expect(req.Req.Question).Should(HaveLen(1))
				Expect(req.Req.Question[0].Name).Should(Equal("example.com."))
				Expect(req.Req.Question[0].Qtype).Should(Equal(dns.TypeA))

				return &model.Response{Res: expectedResponse}, nil
			}

			newCtx, response, err := sut.queryRecords(ctx, "example.com", dns.TypeA)
			Expect(err).Should(Succeed())
			Expect(response).Should(Equal(expectedResponse))

			// Verify budget was decremented
			budget := newCtx.Value(queryBudgetKey{}).(int)
			Expect(budget).Should(Equal(9))
		})

		It("should normalize domain names with FQDN", func() {
			ctx := context.WithValue(context.Background(), queryBudgetKey{}, 10)

			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				Expect(req.Req.Question[0].Name).Should(Equal("example.com."))

				return &model.Response{Res: &dns.Msg{}}, nil
			}

			_, _, err := sut.queryRecords(ctx, "example.com", dns.TypeA)
			Expect(err).Should(Succeed())
		})

		It("should fail when budget is exhausted", func() {
			ctx := context.WithValue(context.Background(), queryBudgetKey{}, 0)

			_, _, err := sut.queryRecords(ctx, "example.com", dns.TypeA)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("budget exhausted"))
		})

		It("should handle upstream query errors", func() {
			ctx := context.WithValue(context.Background(), queryBudgetKey{}, 10)

			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				return nil, errors.New("network error")
			}

			_, _, err := sut.queryRecords(ctx, "example.com", dns.TypeA)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("upstream query failed"))
		})

		It("should query different record types", func() {
			ctx := context.WithValue(context.Background(), queryBudgetKey{}, 10)

			testCases := []uint16{
				dns.TypeA,
				dns.TypeAAAA,
				dns.TypeDNSKEY,
				dns.TypeDS,
				dns.TypeRRSIG,
				dns.TypeNSEC,
				dns.TypeNSEC3,
			}

			for _, qtype := range testCases {
				mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
					Expect(req.Req.Question[0].Qtype).Should(Equal(qtype))

					return &model.Response{Res: &dns.Msg{}}, nil
				}

				_, _, err := sut.queryRecords(ctx, "example.com", qtype)
				Expect(err).Should(Succeed())
			}
		})

		It("should use UDP protocol", func() {
			ctx := context.WithValue(context.Background(), queryBudgetKey{}, 10)

			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				Expect(req.Protocol).Should(Equal(model.RequestProtocolUDP))

				return &model.Response{Res: &dns.Msg{}}, nil
			}

			_, _, err := sut.queryRecords(ctx, "example.com", dns.TypeA)
			Expect(err).Should(Succeed())
		})
	})

	Describe("queryDNSKEY", func() {
		It("should query and extract DNSKEY records", func() {
			ctx := context.WithValue(context.Background(), queryBudgetKey{}, 10)

			dnskey := &dns.DNSKEY{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeDNSKEY,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				Flags:     257,
				Protocol:  3,
				Algorithm: dns.ECDSAP256SHA256,
				PublicKey: "test-key",
			}

			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				Expect(req.Req.Question[0].Qtype).Should(Equal(dns.TypeDNSKEY))

				return &model.Response{
					Res: &dns.Msg{
						Answer: []dns.RR{dnskey},
					},
				}, nil
			}

			newCtx, keys, err := sut.queryDNSKEY(ctx, "example.com")
			Expect(err).Should(Succeed())
			Expect(keys).Should(HaveLen(1))
			Expect(keys[0]).Should(Equal(dnskey))

			// Verify budget was decremented
			budget := newCtx.Value(queryBudgetKey{}).(int)
			Expect(budget).Should(Equal(9))
		})

		It("should handle no DNSKEY records in response", func() {
			ctx := context.WithValue(context.Background(), queryBudgetKey{}, 10)

			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				return &model.Response{
					Res: &dns.Msg{
						Answer: []dns.RR{
							&dns.A{
								Hdr: dns.RR_Header{
									Name:   "example.com.",
									Rrtype: dns.TypeA,
									Class:  dns.ClassINET,
									Ttl:    300,
								},
								A: []byte{192, 0, 2, 1},
							},
						},
					},
				}, nil
			}

			_, _, err := sut.queryDNSKEY(ctx, "example.com")
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("no records"))
		})

		It("should handle upstream errors", func() {
			ctx := context.WithValue(context.Background(), queryBudgetKey{}, 10)

			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				return nil, errors.New("query failed")
			}

			_, _, err := sut.queryDNSKEY(ctx, "example.com")
			Expect(err).Should(HaveOccurred())
		})

		It("should extract multiple DNSKEY records", func() {
			ctx := context.WithValue(context.Background(), queryBudgetKey{}, 10)

			dnskey1 := &dns.DNSKEY{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeDNSKEY,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				Flags:     257, // KSK
				Protocol:  3,
				Algorithm: dns.ECDSAP256SHA256,
				PublicKey: "key1",
			}

			dnskey2 := &dns.DNSKEY{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeDNSKEY,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				Flags:     256, // ZSK
				Protocol:  3,
				Algorithm: dns.ECDSAP256SHA256,
				PublicKey: "key2",
			}

			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				return &model.Response{
					Res: &dns.Msg{
						Answer: []dns.RR{dnskey1, dnskey2},
					},
				}, nil
			}

			_, keys, err := sut.queryDNSKEY(ctx, "example.com")
			Expect(err).Should(Succeed())
			Expect(keys).Should(HaveLen(2))
		})

		It("should handle budget exhaustion", func() {
			ctx := context.WithValue(context.Background(), queryBudgetKey{}, 0)

			_, _, err := sut.queryDNSKEY(ctx, "example.com")
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("budget exhausted"))
		})
	})
})
