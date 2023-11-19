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

	groupName string
	resolvers []*upstreamResolverStatus
}

// NewStrictResolver creates a new strict resolver instance
func NewStrictResolver(
	cfg config.UpstreamGroup, bootstrap *Bootstrap, shouldVerifyUpstreams bool,
) (*StrictResolver, error) {
	logger := log.PrefixedLog(strictResolverType)

	resolvers, err := createResolvers(logger, cfg, bootstrap, shouldVerifyUpstreams)
	if err != nil {
		return nil, err
	}

	return newStrictResolver(cfg, resolvers), nil
}

func newStrictResolver(
	cfg config.UpstreamGroup, resolvers []Resolver,
) *StrictResolver {
	resolverStatuses := make([]*upstreamResolverStatus, 0, len(resolvers))

	for _, r := range resolvers {
		resolverStatuses = append(resolverStatuses, newUpstreamResolverStatus(r))
	}

	r := StrictResolver{
		configurable: withConfig(&cfg),
		typed:        withType(strictResolverType),

		groupName: cfg.Name,
		resolvers: resolverStatuses,
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

	return fmt.Sprintf("%s upstreams '%s (%s)'", strictResolverType, r.groupName, strings.Join(result, ","))
}

// Resolve sends the query request in a strict order to the upstream resolvers
func (r *StrictResolver) Resolve(request *model.Request) (*model.Response, error) {
	logger := log.WithPrefix(request.Log, strictResolverType)

	// start with first resolver
	for i := range r.resolvers {
		timeout := config.GetConfig().Upstreams.Timeout.ToDuration()

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		resolver := r.resolvers[i]
		logger.Debugf("using %s as resolver", resolver.resolver)

		ch := make(chan requestResponse, 1)

		go resolver.resolve(request, ch)

		select {
		case <-ctx.Done():
			// log debug/info that timeout exceeded, call `continue` to try next upstream
			logger.WithField("resolver", r.resolvers[i].resolver).Debug("upstream exceeded timeout, trying next upstream")

			continue
		case result := <-ch:
			if result.err != nil {
				// log error & call `continue` to try next upstream
				logger.Debug("resolution failed from resolver, cause: ", result.err)

				continue
			}

			logger.WithFields(logrus.Fields{
				"resolver": *result.resolver,
				"answer":   util.AnswerToString(result.response.Res.Answer),
			}).Debug("using response from resolver")

			return result.response, nil
		}
	}

	return nil, errors.New("resolution was not successful, no resolver returned an answer in time")
}
