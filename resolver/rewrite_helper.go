package resolver

import (
	"log/slog"
	"strings"

	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
)

// rewriteRequest applies domain rewrites to the DNS request
func rewriteRequest(
	logger *slog.Logger,
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

			// Static message + lazy attrs so Obfuscate runs only when this debug
			// record is actually emitted, not on every rewrite when debug is off.
			logger.Debug("rewriting question domain",
				slog.Any("from", util.DomainLogValuer{Domain: domainOriginal}),
				slog.Any("to", util.DomainLogValuer{Domain: domainRewritten}),
				slog.Any("rewrite", util.DomainLogValuer{Domain: rewriteKey + ":" + rewriteMap[rewriteKey]}))
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
