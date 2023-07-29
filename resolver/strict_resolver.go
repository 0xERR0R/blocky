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
	configurable[*config.UpstreamsConfig]
	typed

	resolversPerClient map[string][]*upstreamResolverStatus
}

// func (r *upstreamResolverStatus) resolve(req *model.Request, ch chan<- requestResponse) {
// 	resp, err := r.resolver.Resolve(req)
// 	if err != nil && !errors.Is(err, context.Canceled) { // ignore `Canceled`: resolver lost the race, not an error
// 		// update the last error time
// 		r.lastErrorTime.Store(time.Now())
// 	}

// 	ch <- requestResponse{
// 		resolver: &r.resolver,
// 		response: resp,
// 		err:      err,
// 	}
// }

// NewStrictResolver creates new resolver instance
func NewStrictResolver(
	cfg config.UpstreamsConfig, bootstrap *Bootstrap, shouldVerifyUpstreams bool,
) (Resolver, error) {
	logger := log.PrefixedLog(strictResolverType)

	upstreamResolvers := cfg.Groups
	resolverGroups := make(map[string][]Resolver, len(upstreamResolvers))

	for name, upstreamCfgs := range upstreamResolvers {
		group := make([]Resolver, 0, len(upstreamCfgs))
		hasValidResolver := false

		for _, u := range upstreamCfgs {
			resolver, err := NewUpstreamResolver(u, bootstrap, shouldVerifyUpstreams)
			if err != nil {
				logger.Warnf("upstream group %s: %v", name, err)

				continue
			}

			if shouldVerifyUpstreams {
				err = testResolver(resolver)
				if err != nil {
					logger.Warn(err)
				} else {
					hasValidResolver = true
				}
			}

			group = append(group, resolver)
		}

		if shouldVerifyUpstreams && !hasValidResolver {
			return nil, fmt.Errorf("no valid upstream for group %s", name)
		}

		resolverGroups[name] = group
	}

	return newStrictResolver(cfg, resolverGroups)
}

func newStrictResolver(
	cfg config.UpstreamsConfig, resolverGroups map[string][]Resolver,
) (*StrictResolver, error) {
	resolversPerClient := make(map[string][]*upstreamResolverStatus, len(resolverGroups))

	for groupName, resolvers := range resolverGroups {
		resolverStatuses := make([]*upstreamResolverStatus, 0, len(resolvers))

		for _, r := range resolvers {
			resolverStatuses = append(resolverStatuses, newUpstreamResolverStatus(r))
		}

		resolversPerClient[groupName] = resolverStatuses
	}

	if len(resolversPerClient[upstreamDefaultCfgName]) == 0 {
		return nil, fmt.Errorf("no external DNS resolvers configured as default upstream resolvers. "+
			"Please configure at least one under '%s' configuration name", upstreamDefaultCfgName)
	}

	r := StrictResolver{
		configurable: withConfig(&cfg),
		typed:        withType(strictResolverType),

		resolversPerClient: resolversPerClient,
	}

	return &r, nil
}

func (r *StrictResolver) Name() string {
	return r.String()
}

func (r *StrictResolver) String() string {
	result := make([]string, 0, len(r.resolversPerClient))

	for name, res := range r.resolversPerClient {
		tmp := make([]string, len(res))
		for i, s := range res {
			tmp[i] = fmt.Sprintf("%s", s.resolver)
		}

		result = append(result, fmt.Sprintf("%s (%s)", name, strings.Join(tmp, ",")))
	}

	return fmt.Sprintf("%s upstreams %q", strictResolverType, strings.Join(result, "; "))
}

// TODO: remove this once logic is separated
func (r *StrictResolver) resolversForClient(request *model.Request) (result []*upstreamResolverStatus) {
	clientIP := request.ClientIP.String()

	// try client names
	for _, cName := range request.ClientNames {
		for clientDefinition, upstreams := range r.resolversPerClient {
			if cName != clientIP && util.ClientNameMatchesGroupName(clientDefinition, cName) {
				result = append(result, upstreams...)
			}
		}
	}

	// try IP
	upstreams, found := r.resolversPerClient[clientIP]

	if found {
		result = append(result, upstreams...)
	}

	// try CIDR
	for cidr, upstreams := range r.resolversPerClient {
		if util.CidrContainsIP(cidr, request.ClientIP) {
			result = append(result, upstreams...)
		}
	}

	if len(result) == 0 {
		// return default
		result = r.resolversPerClient[upstreamDefaultCfgName]
	}

	return result
}

// Resolve sends the query request to multiple upstream resolvers and returns the fastest result
func (r *StrictResolver) Resolve(request *model.Request) (*model.Response, error) {
	logger := log.WithPrefix(request.Log, strictResolverType)

	resolvers := r.resolversForClient(request)

	// start with first resolver
	for i := range resolvers {
		timeout := config.GetConfig().Upstreams.Timeout.ToDuration()

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		// start in new go routine and cancel if

		resolver := resolvers[i]
		ch := make(chan requestResponse, resolverCount)
		go func() {
			resolver.resolve(request, ch)
		}()

		select {
		case <-ctx.Done():
			// log debug/info that timeout exceeded, call `continue` to try next upstream
			logger.WithField("resolver", resolvers[i].resolver).Debug("upstream exceeded timeout, trying next upstream")
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
