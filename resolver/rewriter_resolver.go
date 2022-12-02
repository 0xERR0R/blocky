package resolver

import (
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
	NextResolver
	rewrite          map[string]string
	inner            Resolver
	fallbackUpstream bool
}

func NewRewriterResolver(cfg config.RewriteConfig, inner ChainedResolver) ChainedResolver {
	if len(cfg.Rewrite) == 0 {
		return inner
	}

	for k, v := range cfg.Rewrite {
		cfg.Rewrite[strings.ToLower(k)] = strings.ToLower(v)
	}

	inner.Next(NewNoOpResolver())

	return &RewriterResolver{
		rewrite:          cfg.Rewrite,
		inner:            inner,
		fallbackUpstream: cfg.FallbackUpstream,
	}
}

func (r *RewriterResolver) Name() string {
	return fmt.Sprintf("%s w/ %s", Name(r.inner), defaultName(r))
}

// Configuration returns current resolver configuration
func (r *RewriterResolver) Configuration() (result []string) {
	result = append(result, "rewrite:")
	for key, val := range r.rewrite {
		result = append(result, fmt.Sprintf("  %s = \"%s\"", key, val))
	}

	innerCfg := r.inner.Configuration()
	result = append(result, innerCfg...)

	return result
}

// Resolve uses the inner resolver to resolve the rewritten query
func (r *RewriterResolver) Resolve(request *model.Request) (*model.Response, error) {
	logger := withPrefix(request.Log, "rewriter_resolver")

	original := request.Req

	rewritten, originalNames := r.rewriteRequest(logger, original)
	if rewritten != nil {
		request.Req = rewritten
	}

	logger.WithField("resolver", Name(r.inner)).Trace("go to inner resolver")

	response, err := r.inner.Resolve(request)
	// Test for error after checking for fallbackUpstream

	// Revert the request: must be done before calling r.next
	request.Req = original

	fallbackCondition := err != nil || (response != NoResponse && response.Res.Answer == nil)
	if r.fallbackUpstream && fallbackCondition {
		// Inner resolver had no answer, configuration requests fallback, continue with the normal chain
		logger.WithField("next_resolver", Name(r.next)).Trace("fallback to next resolver")

		return r.next.Resolve(request)
	}

	if err != nil {
		return response, err
	}

	if response == NoResponse {
		// Inner resolver had no response, continue with the normal chain
		logger.WithField("next_resolver", Name(r.next)).Trace("go to next resolver")

		return r.next.Resolve(request)
	}

	// Revert the rewrite in r.inner's response
	if rewritten != nil {
		for i := range originalNames {
			response.Res.Question[i].Name = originalNames[i]

			if i < len(response.Res.Answer) {
				response.Res.Answer[i].Header().Name = originalNames[i]
			}
		}
	}

	return response, nil
}

func (r *RewriterResolver) rewriteRequest(logger *logrus.Entry, request *dns.Msg) (rewritten *dns.Msg, originalNames []string) { //nolint: lll
	originalNames = make([]string, len(request.Question))

	for i := range request.Question {
		nameOriginal := request.Question[i].Name
		originalNames[i] = nameOriginal

		domainOriginal := util.ExtractDomainOnly(nameOriginal)
		domainRewritten, rewriteKey := r.rewriteDomain(domainOriginal)

		if domainRewritten != domainOriginal {
			if rewritten == nil {
				rewritten = request.Copy()
			}

			rewritten.Question[i].Name = dns.Fqdn(domainRewritten)

			logger.WithFields(logrus.Fields{
				"domain":  domainOriginal,
				"rewrite": rewriteKey + ":" + r.rewrite[rewriteKey],
			}).Debugf("rewriting %q to %q", domainOriginal, domainRewritten)
		}
	}

	return rewritten, originalNames
}

func (r *RewriterResolver) rewriteDomain(domain string) (string, string) {
	for k, v := range r.rewrite {
		if strings.HasSuffix(domain, "."+k) {
			newDomain := strings.TrimSuffix(domain, "."+k) + "." + v

			return newDomain, k
		}
	}

	return domain, ""
}
