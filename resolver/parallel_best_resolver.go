package resolver

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync/atomic"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"

	"github.com/mroth/weightedrand/v2"
	"github.com/sirupsen/logrus"
)

const (
	upstreamDefaultCfgName = config.UpstreamDefaultCfgName
	parallelResolverType   = "parallel_best"
	resolverCount          = 2
)

// ParallelBestResolver delegates the DNS message to 2 upstream resolvers and returns the fastest answer
type ParallelBestResolver struct {
	configurable[*config.ParallelBestConfig]
	typed

	resolversPerClient map[string][]*upstreamResolverStatus
}

type upstreamResolverStatus struct {
	resolver      Resolver
	lastErrorTime atomic.Value
}

func newUpstreamResolverStatus(resolver Resolver) *upstreamResolverStatus {
	status := &upstreamResolverStatus{
		resolver: resolver,
	}

	status.lastErrorTime.Store(time.Unix(0, 0))

	return status
}

func (r *upstreamResolverStatus) resolve(req *model.Request, ch chan<- requestResponse) {
	resp, err := r.resolver.Resolve(req)
	if err != nil && !errors.Is(err, context.Canceled) { // ignore `Canceled`: resolver lost the race, not an error
		// update the last error time
		r.lastErrorTime.Store(time.Now())
	}

	ch <- requestResponse{
		response: resp,
		err:      err,
	}
}

type requestResponse struct {
	response *model.Response
	err      error
}

// testResolver sends a test query to verify the resolver is reachable and working
func testResolver(r *UpstreamResolver) error {
	request := newRequest("github.com.", dns.Type(dns.TypeA))

	resp, err := r.Resolve(request)
	if err != nil || resp.RType != model.ResponseTypeRESOLVED {
		return fmt.Errorf("test resolve of upstream server failed: %w", err)
	}

	return nil
}

// NewParallelBestResolver creates new resolver instance
func NewParallelBestResolver(
	cfg config.ParallelBestConfig, bootstrap *Bootstrap, shouldVerifyUpstreams bool,
) (*ParallelBestResolver, error) {
	logger := log.PrefixedLog(parallelResolverType)

	upstreamResolvers := cfg.ExternalResolvers
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

	return newParallelBestResolver(cfg, resolverGroups)
}

func newParallelBestResolver(
	cfg config.ParallelBestConfig, resolverGroups map[string][]Resolver,
) (*ParallelBestResolver, error) {
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

	r := ParallelBestResolver{
		configurable: withConfig(&cfg),
		typed:        withType(parallelResolverType),

		resolversPerClient: resolversPerClient,
	}

	return &r, nil
}

func (r *ParallelBestResolver) Name() string {
	return r.String()
}

func (r *ParallelBestResolver) String() string {
	result := make([]string, 0, len(r.resolversPerClient))

	for name, res := range r.resolversPerClient {
		tmp := make([]string, len(res))
		for i, s := range res {
			tmp[i] = fmt.Sprintf("%s", s.resolver)
		}

		result = append(result, fmt.Sprintf("%s (%s)", name, strings.Join(tmp, ",")))
	}

	return fmt.Sprintf("parallel upstreams '%s'", strings.Join(result, "; "))
}

func (r *ParallelBestResolver) resolversForClient(request *model.Request) (result []*upstreamResolverStatus) {
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
func (r *ParallelBestResolver) Resolve(request *model.Request) (*model.Response, error) {
	logger := log.WithPrefix(request.Log, parallelResolverType)

	resolvers := r.resolversForClient(request)

	if len(resolvers) == 1 {
		logger.WithField("resolver", resolvers[0].resolver).Debug("delegating to resolver")

		return resolvers[0].resolver.Resolve(request)
	}

	r1, r2 := pickRandom(resolvers)
	logger.Debugf("using %s and %s as resolver", r1.resolver, r2.resolver)

	ch := make(chan requestResponse, resolverCount)

	var collectedErrors []error

	logger.WithField("resolver", r1.resolver).Debug("delegating to resolver")

	go r1.resolve(request, ch)

	logger.WithField("resolver", r2.resolver).Debug("delegating to resolver")

	go r2.resolve(request, ch)

	//nolint: gosimple
	for len(collectedErrors) < resolverCount {
		select {
		case result := <-ch:
			if result.err != nil {
				logger.Debug("resolution failed from resolver, cause: ", result.err)
				collectedErrors = append(collectedErrors, result.err)
			} else {
				logger.WithFields(logrus.Fields{
					"resolver": r1.resolver,
					"answer":   util.AnswerToString(result.response.Res.Answer),
				}).Debug("using response from resolver")

				return result.response, nil
			}
		}
	}

	return nil, fmt.Errorf("resolution was not successful, used resolvers: '%s' and '%s' errors: %v",
		r1.resolver, r2.resolver, collectedErrors)
}

// pick 2 different random resolvers from the resolver pool
func pickRandom(resolvers []*upstreamResolverStatus) (resolver1, resolver2 *upstreamResolverStatus) {
	resolver1 = weightedRandom(resolvers, nil)
	resolver2 = weightedRandom(resolvers, resolver1.resolver)

	return
}

func weightedRandom(in []*upstreamResolverStatus, exclude Resolver) *upstreamResolverStatus {
	const errorWindowInSec = 60

	var choices []weightedrand.Choice[*upstreamResolverStatus, uint]

	for _, res := range in {
		var weight float64 = errorWindowInSec

		if time.Since(res.lastErrorTime.Load().(time.Time)) < time.Hour {
			// reduce weight: consider last error time
			lastErrorTime := res.lastErrorTime.Load().(time.Time)
			weight = math.Max(1, weight-(errorWindowInSec-time.Since(lastErrorTime).Minutes()))
		}

		if exclude != res.resolver {
			choices = append(choices, weightedrand.NewChoice(res, uint(weight)))
		}
	}

	c, err := weightedrand.NewChooser(choices...)
	util.LogOnError("can't choose random weighted resolver: ", err)

	return c.Pick()
}
