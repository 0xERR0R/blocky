package resolver

import (
	"fmt"
	"math"
	"strings"
	"sync/atomic"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"

	"github.com/mroth/weightedrand"
	"github.com/sirupsen/logrus"
)

const (
	upstreamDefaultCfgName = "default"
	parallelResolverLogger = "parallel_best_resolver"
	resolverCount          = 2
)

// ParallelBestResolver delegates the DNS message to 2 upstream resolvers and returns the fastest answer
type ParallelBestResolver struct {
	resolversPerClient map[string][]*upstreamResolverStatus
}

type upstreamResolverStatus struct {
	resolver      Resolver
	lastErrorTime atomic.Value
}

type requestResponse struct {
	response *model.Response
	err      error
}

// NewParallelBestResolver creates new resolver instance
func NewParallelBestResolver(upstreamResolvers map[string][]config.Upstream, bootstrap *Bootstrap) (Resolver, error) {
	s := make(map[string][]*upstreamResolverStatus, len(upstreamResolvers))

	for name, res := range upstreamResolvers {
		resolvers := make([]*upstreamResolverStatus, len(res))

		for i, u := range res {
			r, err := NewUpstreamResolver(u, bootstrap)
			if err != nil {
				return nil, err
			}

			resolvers[i] = &upstreamResolverStatus{
				resolver: r,
			}
			resolvers[i].lastErrorTime.Store(time.Unix(0, 0))
		}

		s[name] = resolvers
	}

	if len(s[upstreamDefaultCfgName]) == 0 {
		return nil, fmt.Errorf("no external DNS resolvers configured as default upstream resolvers. "+
			"Please configure at least one under '%s' configuration name", upstreamDefaultCfgName)
	}

	return &ParallelBestResolver{resolversPerClient: s}, nil
}

// Configuration returns current resolver configuration
func (r *ParallelBestResolver) Configuration() (result []string) {
	result = append(result, "upstream resolvers:")
	for name, res := range r.resolversPerClient {
		result = append(result, fmt.Sprintf("- %s", name))
		for _, r := range res {
			result = append(result, fmt.Sprintf("  - %s", r.resolver))
		}
	}

	return
}

func (r ParallelBestResolver) String() string {
	result := make([]string, 0)

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
	// try client names
	for _, cName := range request.ClientNames {
		for clientDefinition, upstreams := range r.resolversPerClient {
			if util.ClientNameMatchesGroupName(clientDefinition, cName) {
				result = append(result, upstreams...)
			}
		}
	}

	// try IP
	upstreams, found := r.resolversPerClient[request.ClientIP.String()]

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
	logger := request.Log.WithField("prefix", parallelResolverLogger)

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

	go resolve(request, r1, ch)

	logger.WithField("resolver", r2.resolver).Debug("delegating to resolver")

	go resolve(request, r2, ch)

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

	var choices []weightedrand.Choice

	for _, res := range in {
		var weight float64 = errorWindowInSec

		if time.Since(res.lastErrorTime.Load().(time.Time)) < time.Hour {
			// reduce weight: consider last error time
			lastErrorTime := res.lastErrorTime.Load().(time.Time)
			weight = math.Max(1, weight-(errorWindowInSec-time.Since(lastErrorTime).Minutes()))
		}

		if exclude != res.resolver {
			choices = append(choices, weightedrand.Choice{
				Item:   res,
				Weight: uint(weight),
			})
		}
	}

	c, _ := weightedrand.NewChooser(choices...)

	return c.Pick().(*upstreamResolverStatus)
}

func resolve(req *model.Request, resolver *upstreamResolverStatus, ch chan<- requestResponse) {
	resp, err := resolver.resolver.Resolve(req)

	// update the last error time
	if err != nil {
		resolver.lastErrorTime.Store(time.Now())
	}
	ch <- requestResponse{
		response: resp,
		err:      err,
	}
}
