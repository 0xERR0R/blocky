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

// ConditionalUpstreamResolver delegates DNS question to other DNS resolver dependent on domain name in question
type ConditionalUpstreamResolver struct {
	NextResolver
	mapping map[string]Resolver
	rewrite map[string]string
}

// NewConditionalUpstreamResolver returns new resolver instance
func NewConditionalUpstreamResolver(cfg config.ConditionalUpstreamConfig) ChainedResolver {
	m := make(map[string]Resolver)
	rewrite := make(map[string]string)

	for domain, upstream := range cfg.Mapping.Upstreams {
		upstreams := make(map[string][]config.Upstream)
		upstreams[upstreamDefaultCfgName] = upstream
		m[strings.ToLower(domain)] = NewParallelBestResolver(upstreams)
	}

	for k, v := range cfg.Rewrite {
		rewrite[strings.ToLower(k)] = strings.ToLower(v)
	}

	return &ConditionalUpstreamResolver{mapping: m, rewrite: rewrite}
}

// Configuration returns current configuration
func (r *ConditionalUpstreamResolver) Configuration() (result []string) {
	if len(r.mapping) > 0 {
		for key, val := range r.mapping {
			result = append(result, fmt.Sprintf("%s = \"%s\"", key, val))
		}

		if len(r.rewrite) > 0 {
			result = append(result, "rewrite:")
			for key, val := range r.rewrite {
				result = append(result, fmt.Sprintf("%s = \"%s\"", key, val))
			}
		}
	} else {
		result = []string{"deactivated"}
	}

	return
}

func (r *ConditionalUpstreamResolver) applyRewrite(domain string) string {
	for k, v := range r.rewrite {
		if strings.HasSuffix(domain, "."+k) {
			return strings.TrimSuffix(domain, "."+k) + "." + v
		}
	}

	return domain
}

// Resolve uses the conditional resolver to resolve the query
func (r *ConditionalUpstreamResolver) Resolve(request *model.Request) (*model.Response, error) {
	logger := withPrefix(request.Log, "conditional_resolver")

	if len(r.mapping) > 0 {
		domainFromQuestion := r.applyRewrite(util.ExtractDomain(request.Req.Question[0]))
		domain := domainFromQuestion

		if !strings.Contains(domainFromQuestion, ".") {
			if resolver, found := r.mapping["."]; found {
				return r.internalResolve(resolver, domainFromQuestion, domain, request)
			}
		} else {
			// try with domain with and without sub-domains
			for len(domain) > 0 {
				if resolver, found := r.mapping[domain]; found {
					return r.internalResolve(resolver, domainFromQuestion, domain, request)
				}

				if i := strings.Index(domain, "."); i >= 0 {
					domain = domain[i+1:]
				} else {
					break
				}
			}
		}
	}

	logger.WithField("next_resolver", Name(r.next)).Trace("go to next resolver")

	return r.next.Resolve(request)
}

func (r *ConditionalUpstreamResolver) internalResolve(reso Resolver, doFQ, do string,
	req *model.Request) (*model.Response, error) {
	// internal request resolution
	logger := withPrefix(req.Log, "conditional_resolver")

	req.Req.Question[0].Name = dns.Fqdn(doFQ)
	response, err := reso.Resolve(req)

	if err == nil {
		response.Reason = "CONDITIONAL"
		response.RType = model.ResponseTypeCONDITIONAL
		response.Res.Question[0].Name = req.Req.Question[0].Name
	}

	var answer string
	if response != nil {
		answer = util.AnswerToString(response.Res.Answer)
	}

	logger.WithFields(logrus.Fields{
		"answer":   answer,
		"domain":   do,
		"upstream": reso,
	}).Debugf("received response from conditional upstream")

	return response, err
}
