package resolver

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/creasty/defaults"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("Log entries of a query", func() {
	var (
		ctx     context.Context
		entries *test.Hook
		next    *mockResolver
	)

	// logAt gives the context a logger of its own with the level: the global logger has
	// the level of the whole suite.
	logAt := func(level logrus.Level) {
		logger, hook := test.NewNullLogger()
		logger.SetLevel(level)

		ctx, _ = log.NewCtx(ctx, logrus.NewEntry(logger))
		entries = hook
	}

	BeforeEach(func() {
		var cancel context.CancelFunc

		ctx, cancel = context.WithCancel(context.Background())
		DeferCleanup(cancel)

		logAt(logrus.TraceLevel)

		next = &mockResolver{AnswerFn: autoAnswer}
		next.On("Resolve", mock.Anything)
	})

	// fieldsOf returns the fields of each entry whose message starts with message.
	fieldsOf := func(message string) []logrus.Fields {
		var fields []logrus.Fields

		for _, entry := range entries.AllEntries() {
			if strings.HasPrefix(entry.Message, message) {
				fields = append(fields, entry.Data)
			}
		}

		return fields
	}

	newCaching := func() *CachingResolver {
		cfg := config.Caching{}
		Expect(defaults.Set(&cfg)).Should(Succeed())

		sut, err := NewCachingResolver(ctx, cfg, config.DNSSEC{}, nil)
		Expect(err).Should(Succeed())

		sut.Next(next)

		return sut
	}

	DescribeTable("name the next resolver when a resolver passes the query on",
		func(newSUT func() ChainedResolver, prefix, message string) {
			sut := newSUT()
			sut.Next(next)

			_, err := sut.Resolve(ctx, newRequest("example.com.", A))
			Expect(err).Should(Succeed())

			Expect(fieldsOf(message)).Should(ConsistOf(SatisfyAll(
				HaveKeyWithValue("prefix", prefix),
				HaveKeyWithValue("next_resolver", "mock"),
			)))
		},
		Entry("the caching resolver, without an entry for the name",
			func() ChainedResolver { return newCaching() },
			"caching", "not in cache: go to next resolver"),
		Entry("the custom DNS resolver, without a record for the name",
			func() ChainedResolver {
				return NewCustomDNSResolver(config.CustomDNS{
					Mapping: config.CustomDNSMapping{"custom.domain": {&dns.A{A: net.ParseIP("192.0.2.1")}}},
				})
			},
			"custom_dns", "go to next resolver"),
		Entry("the conditional upstream resolver, without an upstream for the name",
			func() ChainedResolver {
				sut, err := NewConditionalUpstreamResolver(
					ctx, config.ConditionalUpstream{}, defaultUpstreamsConfig, systemResolverBootstrap)
				Expect(err).Should(Succeed())

				return sut
			},
			"conditional_upstream", "go to next resolver"),
		Entry("the hosts file resolver, without a host of the name",
			func() ChainedResolver {
				sut, err := NewHostsFileResolver(ctx, config.HostsFile{
					Sources: []config.BytesSource{config.TextBytesSource("192.0.2.1 host.example")},
					Loading: config.SourceLoading{RefreshPeriod: -1, MaxErrorsPerSource: 5},
				}, systemResolverBootstrap)
				Expect(err).Should(Succeed())

				return sut
			},
			"hosts_file", "go to next resolver"),
	)

	It("name the domain of a cache hit", func() {
		sut := newCaching()

		// the first answer fills the cache
		for range 2 {
			_, err := sut.Resolve(ctx, newRequest("example.com.", A))
			Expect(err).Should(Succeed())
		}

		Expect(fieldsOf("domain is cached")).Should(ConsistOf(SatisfyAll(
			HaveKeyWithValue("prefix", "caching"),
			HaveKeyWithValue(logFieldDomain, "example.com"),
		)))
	})

	It("name the domain of a cache entry that cannot be unpacked, which counts as a miss", func() {
		// at the level where no other entry of the caching resolver has the domain
		logAt(logrus.InfoLevel)

		sut := newCaching()

		malformed := []byte{1, 2, 3}
		sut.resultCache.Put(util.GenerateCacheKey(A, "example.com"), &malformed, time.Minute)

		Expect(sut.Resolve(ctx, newRequest("example.com.", A))).
			Should(BeDNSRecord("example.com.", A, autoAnswerIPv4.String()))

		Expect(fieldsOf("can't unpack cached entry")).Should(ConsistOf(
			HaveKeyWithValue(logFieldDomain, "example.com"),
		))
	})

	It("name the answer the strict resolver uses, and its resolver", func() {
		sut := newStrictResolver(config.NewUpstreamGroup("test", defaultUpstreamsConfig, nil), []Resolver{next})

		response, err := sut.Resolve(ctx, newRequest("example.com.", A))
		Expect(err).Should(Succeed())

		Expect(fieldsOf("using response from resolver")).Should(ConsistOf(SatisfyAll(
			HaveKeyWithValue("prefix", strictResolverType),
			HaveKeyWithValue(logFieldAnswer, util.AnswerToString(response.Res.Answer)),
			HaveKey("resolver"),
		)))
	})

	It("name the resolvers the parallel resolver asks, and the one whose answer it uses", func() {
		other := &mockResolver{AnswerFn: autoAnswer}
		other.On("Resolve", mock.Anything)

		sut := newParallelBestResolver(
			config.NewUpstreamGroup("test", defaultUpstreamsConfig, nil), []Resolver{next, other})

		response, err := sut.Resolve(ctx, newRequest("example.com.", A))
		Expect(err).Should(Succeed())

		// by identity: the resolver that lost the race may still be at work
		Expect(fieldsOf("delegating to resolver")).Should(ConsistOf(
			HaveKeyWithValue("resolver", BeIdenticalTo(next)),
			HaveKeyWithValue("resolver", BeIdenticalTo(other)),
		))
		Expect(fieldsOf("using response from resolver")).Should(ConsistOf(SatisfyAll(
			HaveKeyWithValue("prefix", parallelResolverType),
			HaveKeyWithValue("resolver", Or(BeIdenticalTo(next), BeIdenticalTo(other))),
			HaveKeyWithValue(logFieldAnswer, util.AnswerToString(response.Res.Answer)),
		)))
	})

	It("have the names of the client after the client names resolver", func() {
		sut, err := NewClientNamesResolver(ctx, config.ClientLookup{}, defaultUpstreamsConfig, nil)
		Expect(err).Should(Succeed())

		next.ResolveFn = func(ctx context.Context, _ *model.Request) (*model.Response, error) {
			log.FromCtx(ctx).Info("after the client names resolver")

			return &model.Response{Res: new(dns.Msg)}, nil
		}
		sut.Next(next)

		_, err = sut.Resolve(ctx, newRequestWithClientID("example.com.", A, "192.0.2.1", "client123"))
		Expect(err).Should(Succeed())

		Expect(fieldsOf("after the client names resolver")).Should(ConsistOf(
			HaveKeyWithValue("client_names", "client123"),
		))
	})

	It("get a field of debug entries only from a logger that logs them", func() {
		atTrace := log.FromCtx(ctx)
		Expect(withDebugField(atTrace, "name", "value").Data).Should(HaveKeyWithValue("name", "value"))

		logger, _ := test.NewNullLogger()
		atInfo := logrus.NewEntry(logger)
		Expect(withDebugField(atInfo, "name", "value")).Should(BeIdenticalTo(atInfo))
	})
})
