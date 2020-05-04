package resolver

import (
	"blocky/config"
	"blocky/util"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

// ConditionalUpstreamResolver delegates DNS question to other DNS resolver dependent on domain name in question
type ConditionalUpstreamResolver struct {
	NextResolver
	mapping map[string]Resolver
}

func NewConditionalUpstreamResolver(cfg config.ConditionalUpstreamConfig) ChainedResolver {
	m := make(map[string]Resolver)
	for domain, upstream := range cfg.Mapping {
		m[strings.ToLower(domain)] = NewUpstreamResolver(upstream)
	}

	return &ConditionalUpstreamResolver{mapping: m}
}

func (r *ConditionalUpstreamResolver) Configuration() (result []string) {
	if len(r.mapping) > 0 {
		for key, val := range r.mapping {
			result = append(result, fmt.Sprintf("%s = \"%s\"", key, val))
		}
	} else {
		result = []string{"deactivated"}
	}

	return
}

func (r *ConditionalUpstreamResolver) Resolve(request *Request) (*Response, error) {
	logger := withPrefix(request.Log, "conditional_resolver")

	if len(r.mapping) > 0 {
		for _, question := range request.Req.Question {
			domain := util.ExtractDomain(question)

			// try with domain with and without sub-domains
			for len(domain) > 0 {
				r, found := r.mapping[domain]
				if found {
					response, err := r.Resolve(request)
					if err == nil {
						response.Reason = "CONDITIONAL"
						response.RType = CONDITIONAL
					}

					var answer string
					if response != nil {
						answer = util.AnswerToString(response.Res.Answer)
					}

					logger.WithFields(logrus.Fields{
						"answer":   answer,
						"domain":   domain,
						"upstream": r,
					}).Debugf("received response from conditional upstream")

					return response, err
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
