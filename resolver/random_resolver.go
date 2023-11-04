package resolver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/sirupsen/logrus"
)

const (
	randomResolverType = "random"
)

// RandomResolver delegates the DNS message to one random upstream resolver
// if it can't provide the answer in time a different resolver is chosen randomly
// resolvers who fail to response get a penalty and are less likely to be chosen for the next request
type RandomResolver struct {
	configurable[*config.UpstreamGroup]
	typed

	groupName string
	resolvers []*upstreamResolverStatus
}

// NewRandomResolver creates a new random resolver instance
func NewRandomResolver(
	cfg config.UpstreamGroup, bootstrap *Bootstrap, shoudVerifyUpstreams bool,
) (*RandomResolver, error) {
	logger := log.PrefixedLog(randomResolverType)

	resolvers, err := createResolvers(logger, cfg, bootstrap, shoudVerifyUpstreams)
	if err != nil {
		return nil, err
	}

	return newRandomResolver(cfg, resolvers), nil
}

func newRandomResolver(
	cfg config.UpstreamGroup, resolvers []Resolver,
) *RandomResolver {
	resolverStatuses := make([]*upstreamResolverStatus, 0, len(resolvers))

	for _, r := range resolvers {
		resolverStatuses = append(resolverStatuses, newUpstreamResolverStatus(r))
	}

	r := RandomResolver{
		configurable: withConfig(&cfg),
		typed:        withType(randomResolverType),

		groupName: cfg.Name,
		resolvers: resolverStatuses,
	}

	return &r
}

func (r *RandomResolver) Name() string {
	return r.String()
}

func (r *RandomResolver) String() string {
	result := make([]string, len(r.resolvers))
	for i, s := range r.resolvers {
		result[i] = fmt.Sprintf("%s", s.resolver)
	}

	return fmt.Sprintf("%s upstreams '%s (%s)'", randomResolverType, r.groupName, strings.Join(result, ","))
}

// Resolve sends the query request to a random upstream resolver
func (r *RandomResolver) Resolve(request *model.Request) (*model.Response, error) {
	logger := log.WithPrefix(request.Log, randomResolverType)

	if len(r.resolvers) == 1 {
		logger.WithField("resolver", r.resolvers[0].resolver).Debug("delegating to resolver")

		return r.resolvers[0].resolver.Resolve(request)
	}

	timeout := config.GetConfig().Upstreams.Timeout.ToDuration()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// first try
	r1 := weightedRandom(r.resolvers, nil)
	logger.Debugf("using %s as resolver", r1.resolver)

	ch := make(chan requestResponse, 1)

	go r1.resolve(request, ch)

	select {
	case <-ctx.Done():
		logger.WithField("resolver", r1.resolver).Debug("upstream exceeded timeout, trying other upstream")
		r1.lastErrorTime.Store(time.Now())
	case result := <-ch:
		if result.err != nil {
			logger.Debug("resolution failed from resolver, cause: ", result.err)
		} else {
			logger.WithFields(logrus.Fields{
				"resolver": *result.resolver,
				"answer":   util.AnswerToString(result.response.Res.Answer),
			}).Debug("using response from resolver")

			return result.response, nil
		}
	}

	// second try
	r2 := weightedRandom(r.resolvers, r1.resolver)
	logger.Debugf("using %s as second resolver", r2.resolver)

	ch = make(chan requestResponse, 1)

	r2.resolve(request, ch)

	result := <-ch
	if result.err != nil {
		logger.Debug("resolution failed from resolver, cause: ", result.err)

		return nil, errors.New("resolution was not successful, no resolver returned answer in time")
	}

	logger.WithFields(logrus.Fields{
		"resolver": *result.resolver,
		"answer":   util.AnswerToString(result.response.Res.Answer),
	}).Debug("using response from resolver")

	return result.response, nil
}
