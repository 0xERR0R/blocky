package resolver

import (
	"context"
	"errors"
	"strings"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// rewriteRequest applies domain rewrites to the DNS request
func rewriteRequest(
	logger *logrus.Entry,
	request *dns.Msg,
	rewriteMap map[string]string,
) (rewritten *dns.Msg, originalNames map[string]string) {
	if len(rewriteMap) == 0 {
		return nil, nil
	}

	originalNames = make(map[string]string, len(request.Question))

	for i := range request.Question {
		nameOriginal := request.Question[i].Name

		domainOriginal := util.ExtractDomainOnly(nameOriginal)
		domainRewritten, rewriteKey := rewriteDomain(domainOriginal, rewriteMap)

		if domainRewritten != domainOriginal {
			rewrittenFQDN := dns.Fqdn(domainRewritten)

			originalNames[rewrittenFQDN] = nameOriginal

			if rewritten == nil {
				rewritten = request.Copy()
			}

			rewritten.Question[i].Name = rewrittenFQDN

			logger.WithFields(logrus.Fields{
				"rewrite": util.Obfuscate(rewriteKey) + ":" + util.Obfuscate(rewriteMap[rewriteKey]),
			}).Debugf("rewriting %q to %q", util.Obfuscate(domainOriginal), util.Obfuscate(domainRewritten))
		}
	}

	return rewritten, originalNames
}

// rewriteDomain applies rewrite rules to a domain name
func rewriteDomain(domain string, rewriteMap map[string]string) (string, string) {
	if len(rewriteMap) == 0 {
		return domain, ""
	}

	domain = strings.ToLower(domain)

	for k, v := range rewriteMap {
		if prefix, ok := strings.CutSuffix(domain, "."+k); ok {
			return prefix + "." + v, k
		}
	}

	return domain, ""
}

// shouldFallbackUpstream reports whether a query the resolver answered itself,
// with an error or without an answer, should be retried with its original name
// on the rest of the chain. See `fallbackUpstream` in the documentation.
//
// Callers must delegate queries they did not answer themselves before reaching
// this: a response passed through from the next resolver must not go there again.
func shouldFallbackUpstream(cfg *config.RewriterConfig, response *model.Response, err error) bool {
	if !cfg.FallbackUpstream || len(cfg.Rewrite) == 0 {
		return false
	}

	if err != nil {
		// a dead context fails on the next resolver too, and its error is the useful one
		return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
	}

	return response != nil && response != NoResponse && response.Res != nil && len(response.Res.Answer) == 0
}

// revertRewritesInResponse reverts domain rewrites in the DNS response
func revertRewritesInResponse(response *dns.Msg, originalNames map[string]string) {
	if len(originalNames) == 0 {
		return
	}

	n := max(len(response.Question), len(response.Answer))
	for i := range n {
		if i < len(response.Question) {
			original, ok := originalNames[response.Question[i].Name]
			if ok {
				response.Question[i].Name = original
			}
		}

		if i < len(response.Answer) {
			original, ok := originalNames[response.Answer[i].Header().Name]
			if ok {
				response.Answer[i].Header().Name = original
			}
		}
	}
}
