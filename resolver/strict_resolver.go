package resolver

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"

	"github.com/sirupsen/logrus"
)

const (
	strictResolverType = "strict"
)

// StrictResolver delegates the DNS message strictly to the first configured upstream resolver
// if it can't provide the answer in time the next resolver is used
type StrictResolver struct {
	configurable[*config.UpstreamGroup]
	typed

	resolvers []*upstreamResolverStatus
}

// NewStrictResolver creates a new strict resolver instance
func NewStrictResolver(
	ctx context.Context, cfg config.UpstreamGroup, bootstrap *Bootstrap,
) (*StrictResolver, error) {
	logger := log.PrefixedLog(strictResolverType)

	resolvers, err := createResolvers(ctx, logger, cfg, bootstrap)
	if err != nil {
		return nil, err
	}

	return newStrictResolver(cfg, resolvers), nil
}

func newStrictResolver(
	cfg config.UpstreamGroup, resolvers []Resolver,
) *StrictResolver {
	r := StrictResolver{
		configurable: withConfig(&cfg),
		typed:        withType(strictResolverType),

		resolvers: newUpstreamResolverStatuses(resolvers),
	}

	return &r
}

func (r *StrictResolver) Name() string {
	return r.String()
}

func (r *StrictResolver) String() string {
	result := make([]string, len(r.resolvers))
	for i, s := range r.resolvers {
		result[i] = fmt.Sprintf("%s", s.resolver)
	}

	return fmt.Sprintf("%s upstreams '%s (%s)'", strictResolverType, r.cfg.Name, strings.Join(result, ","))
}

// Resolve sends the query request in a strict order to the upstream resolvers
func (r *StrictResolver) Resolve(ctx context.Context, request *model.Request) (*model.Response, error) {
	logger := log.WithPrefix(request.Log, strictResolverType)

	// start with first resolver
	for _, resolver := range r.resolvers {
		logger.Debugf("using %s as resolver", resolver.resolver)

		resp, err := resolver.resolve(ctx, request)
		if err != nil {
			// log error and try next upstream
			logger.WithField("resolver", resolver.resolver).Debug("resolution failed from resolver, cause: ", err)

			continue
		}

		logger.WithFields(logrus.Fields{
			"resolver": *resolver,
			"answer":   util.AnswerToString(resp.Res.Answer),
		}).Debug("using response from resolver")

		return resp, nil
	}

	return nil, errors.New("resolution was not successful, no resolver returned an answer in time")
}
