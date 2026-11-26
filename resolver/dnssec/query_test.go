package dnssec

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

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
			ctx := withQueryBudget(context.Background(), 5)
			err := sut.consumeQueryBudget(ctx)
			Expect(err).Should(Succeed())
		})

		It("should fail when budget is exhausted", func() {
			ctx := withQueryBudget(context.Background(), 0)
			err := sut.consumeQueryBudget(ctx)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("budget exhausted"))
		})

		It("should fail when budget is negative", func() {
			ctx := withQueryBudget(context.Background(), -1)
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

	Describe("withQueryBudget", func() {
		It("should share one budget with every derived context", func() {
			ctx := withQueryBudget(context.Background(), 2)
			derived := WithClientContext(ctx, nil, nil, "", "view")

			Expect(sut.consumeQueryBudget(ctx)).Should(Succeed())
			Expect(sut.consumeQueryBudget(derived)).Should(Succeed())
			Expect(sut.consumeQueryBudget(ctx)).Should(MatchError(ContainSubstring("budget exhausted")))
		})
	})

	Describe("budgetFrom", func() {
		It("should compute each NSEC3 hash once and no more hashes than the budget holds", func() {
			b := budgetFrom(withQueryBudget(ctx, 0))

			for i := range maxNSEC3Hashes {
				name := fmt.Sprintf("n%d.example.", i)

				Expect(b.nsec3Hash(name, "", 0)).Should(Equal(nsec3Hash(name, "", 0)))
				Expect(b.nsec3Hash(strings.ToUpper(name), "", 0)).Should(Equal(nsec3Hash(name, "", 0)))
			}

			Expect(b.hashes.Load()).Should(BeEquivalentTo(maxNSEC3Hashes))

			// One more is refused, and a hash that is known is still there
			Expect(b.nsec3Hash("more.example.", "", 0)).Should(BeEmpty())
			Expect(b.nsec3Hash("n0.example.", "", 0)).Should(Equal(nsec3Hash("n0.example.", "", 0)))
			Expect(b.hashes.Load()).Should(BeEquivalentTo(maxNSEC3Hashes))
		})

		It("should keep no zone status that a validation finds after it ran out of budget", func() {
			validation := withQueryBudget(ctx, 0)
			sut.setCachedValidation(validation, "before.example.", ValidationResultBogus)

			for i := range maxNSEC3Hashes + 1 {
				budgetFrom(validation).nsec3Hash(fmt.Sprintf("n%d.example.", i), "", 0)
			}

			sut.setCachedValidation(validation, "after.example.", ValidationResultBogus)

			_, found := sut.getCachedValidation(ctx, "before.example.")
			Expect(found).Should(BeTrue())

			_, found = sut.getCachedValidation(ctx, "after.example.")
			Expect(found).Should(BeFalse())
		})

		It("should keep no zone status for a context that belongs to no validation", func() {
			Expect(budgetFrom(ctx)).Should(BeNil())

			sut.setCachedValidation(ctx, "outside.example.", ValidationResultSecure)

			_, found := sut.getCachedValidation(ctx, "outside.example.")
			Expect(found).Should(BeFalse())
		})
	})

	Describe("queryRecords", func() {
		It("should query upstream with DNSSEC enabled", func() {
			ctx := withQueryBudget(context.Background(), 10)

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

			response, err := sut.queryRecords(ctx, "example.com", dns.TypeA)
			Expect(err).Should(Succeed())
			Expect(response).Should(Equal(expectedResponse))

			// Verify budget was decremented
			Expect(ctx.Value(queryBudgetKey{}).(*atomic.Int64).Load()).Should(Equal(int64(9)))
		})

		It("should normalize domain names with FQDN", func() {
			ctx := withQueryBudget(context.Background(), 10)

			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				Expect(req.Req.Question[0].Name).Should(Equal("example.com."))

				return &model.Response{Res: &dns.Msg{}}, nil
			}

			_, err := sut.queryRecords(ctx, "example.com", dns.TypeA)
			Expect(err).Should(Succeed())
		})

		It("should fail when budget is exhausted", func() {
			ctx := withQueryBudget(context.Background(), 0)

			_, err := sut.queryRecords(ctx, "example.com", dns.TypeA)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("budget exhausted"))
		})

		It("should treat a truncated reply as a failed query", func() {
			ctx := withQueryBudget(context.Background(), 10)

			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				return &model.Response{Res: &dns.Msg{Truncated: true}}, nil
			}

			_, err := sut.queryRecords(ctx, "example.com", dns.TypeDS)
			Expect(err).Should(MatchError(ContainSubstring("truncated")))

			_, _, err = sut.queryDNSKEY(ctx, "example.com")
			Expect(err).Should(MatchError(errDNSKEYUnavailable))
		})

		It("should handle upstream query errors", func() {
			ctx := withQueryBudget(context.Background(), 10)

			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				return nil, errors.New("network error")
			}

			_, err := sut.queryRecords(ctx, "example.com", dns.TypeA)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("upstream query failed"))
		})

		It("should query different record types", func() {
			ctx := withQueryBudget(context.Background(), 10)

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

				_, err := sut.queryRecords(ctx, "example.com", qtype)
				Expect(err).Should(Succeed())
			}
		})

		It("should use UDP protocol", func() {
			ctx := withQueryBudget(context.Background(), 10)

			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				Expect(req.Protocol).Should(Equal(model.RequestProtocolUDP))

				return &model.Response{Res: &dns.Msg{}}, nil
			}

			_, err := sut.queryRecords(ctx, "example.com", dns.TypeA)
			Expect(err).Should(Succeed())
		})
	})

	Describe("queryDNSKEY", func() {
		It("should query and extract DNSKEY records", func() {
			ctx := withQueryBudget(context.Background(), 10)

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

			answer, keys, err := sut.queryDNSKEY(ctx, "example.com")
			Expect(err).Should(Succeed())
			Expect(answer).Should(Equal([]dns.RR{dnskey}))
			Expect(keys).Should(HaveLen(1))
			Expect(keys[0]).Should(Equal(dnskey))
		})

		It("should treat SERVFAIL as unavailable keys", func() {
			ctx := withQueryBudget(context.Background(), 10)

			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				return &model.Response{Res: &dns.Msg{Rcode: dns.RcodeServerFailure}}, nil
			}

			_, _, err := sut.queryDNSKEY(ctx, "example.com")
			Expect(err).Should(MatchError(errDNSKEYUnavailable))
		})

		It("should treat NXDOMAIN as unavailable keys", func() {
			ctx := withQueryBudget(context.Background(), 10)

			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				return &model.Response{Res: &dns.Msg{Rcode: dns.RcodeNameError}}, nil
			}

			_, _, err := sut.queryDNSKEY(ctx, "example.com")
			Expect(err).Should(MatchError(errDNSKEYUnavailable))
		})

		It("should handle no DNSKEY records in response", func() {
			ctx := withQueryBudget(context.Background(), 10)

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
			ctx := withQueryBudget(context.Background(), 10)

			mockUpstream.ResolveFn = func(ctx context.Context, req *model.Request) (*model.Response, error) {
				return nil, errors.New("query failed")
			}

			_, _, err := sut.queryDNSKEY(ctx, "example.com")
			Expect(err).Should(MatchError(errDNSKEYUnavailable))
		})

		It("should extract multiple DNSKEY records", func() {
			ctx := withQueryBudget(context.Background(), 10)

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
			ctx := withQueryBudget(context.Background(), 0)

			_, _, err := sut.queryDNSKEY(ctx, "example.com")
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("budget exhausted"))
		})
	})
})
