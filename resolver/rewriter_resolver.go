package resolver

import (
	"context"
	"fmt"
	"strings"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// RewriterResolver is different from other resolvers, in the sense that
// it creates a branch in the resolver chain.
// The branch is where the rewrite is active. If the branch doesn't
// yield a result, the normal resolving is continued.
type RewriterResolver struct {
	configurable[*config.RewriterConfig]
	NextResolver
	typed

	inner Resolver
}

func NewRewriterResolver(cfg config.RewriterConfig, inner ChainedResolver) ChainedResolver {
	if len(cfg.Rewrite) == 0 {
		return inner
	}

	// ensures that the rewrites map contains all rewrites in lower case
	for k, v := range cfg.Rewrite {
		cfg.Rewrite[strings.ToLower(k)] = strings.ToLower(v)
	}

	inner.Next(NewNoOpResolver())

	return &RewriterResolver{
		configurable: withConfig(&cfg),
		typed:        withType("rewrite"),

		inner: inner,
	}
}

func (r *RewriterResolver) Name() string {
	return fmt.Sprintf("%s w/ %s", Name(r.inner), r.Type())
}

// LogConfig implements `config.Configurable`.
func (r *RewriterResolver) LogConfig(logger *logrus.Entry) {
	LogResolverConfig(r.inner, logger)

	r.cfg.LogConfig(logger)
}

// Resolve uses the inner resolver to resolve the rewritten query
func (r *RewriterResolver) Resolve(ctx context.Context, request *model.Request) (*model.Response, error) {
	ctx, logger := r.log(ctx)

	original := request.Req

	rewritten, originalNames := r.rewriteRequest(logger, original)
	if rewritten != nil {
		request.Req = rewritten
	}

	logger.WithField("resolver", Name(r.inner)).Trace("go to inner resolver")

	response, err := r.inner.Resolve(ctx, request)
	// Test for error after checking for fallbackUpstream

	// Revert the request: must be done before calling r.next
	request.Req = original

	fallbackCondition := err != nil || (response != NoResponse && response.Res.Answer == nil)
	if r.cfg.FallbackUpstream && fallbackCondition {
		// Inner resolver had no answer, configuration requests fallback, continue with the normal chain
		logger.WithField("next_resolver", Name(r.next)).Trace("fallback to next resolver")

		return r.next.Resolve(ctx, request)
	}

	if err != nil {
		return response, err
	}

	if response == NoResponse {
		// Inner resolver had no response, continue with the normal chain
		logger.WithField("next_resolver", Name(r.next)).Trace("go to next resolver")

		return r.next.Resolve(ctx, request)
	}

	if rewritten == nil {
		return response, nil
	}

	// Revert the rewrite in r.inner's response

	n := max(len(response.Res.Question), len(response.Res.Answer))
	for i := 0; i < n; i++ {
		if i < len(response.Res.Question) {
			original, ok := originalNames[response.Res.Question[i].Name]
			if ok {
				response.Res.Question[i].Name = original
			}
		}

		if i < len(response.Res.Answer) {
			original, ok := originalNames[response.Res.Answer[i].Header().Name]
			if ok {
				response.Res.Answer[i].Header().Name = original
			}
		}
	}

	return response, nil
}

func (r *RewriterResolver) rewriteRequest(
	logger *logrus.Entry, request *dns.Msg,
) (rewritten *dns.Msg, originalNames map[string]string) {
	originalNames = make(map[string]string, len(request.Question))

	for i := range request.Question {
		nameOriginal := request.Question[i].Name

		domainOriginal := util.ExtractDomainOnly(nameOriginal)
		domainRewritten, rewriteKey := r.rewriteDomain(domainOriginal)

		if domainRewritten != domainOriginal {
			rewrittenFQDN := dns.Fqdn(domainRewritten)

			originalNames[rewrittenFQDN] = nameOriginal

			if rewritten == nil {
				rewritten = request.Copy()
			}

			rewritten.Question[i].Name = rewrittenFQDN

			logger.WithFields(logrus.Fields{
				"rewrite": util.Obfuscate(rewriteKey) + ":" + util.Obfuscate(r.cfg.Rewrite[rewriteKey]),
			}).Debugf("rewriting %q to %q", util.Obfuscate(domainOriginal), util.Obfuscate(domainRewritten))
		}
	}

	return rewritten, originalNames
}

func (r *RewriterResolver) rewriteDomain(domain string) (string, string) {
	for k, v := range r.cfg.Rewrite {
		if strings.HasSuffix(domain, "."+k) {
			newDomain := strings.TrimSuffix(domain, "."+k) + "." + v

			return newDomain, k
		}
	}

	return domain, ""
}
