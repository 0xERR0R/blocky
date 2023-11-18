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
	upstreamDefaultCfgName    = config.UpstreamDefaultCfgName
	parallelResolverType      = "parallel_best"
	randomResolverType        = "random"
	parallelBestResolverCount = 2
)

// ParallelBestResolver delegates the DNS message to 2 upstream resolvers and returns the fastest answer
type ParallelBestResolver struct {
	configurable[*config.UpstreamGroup]
	typed

	groupName string
	resolvers []*upstreamResolverStatus

	resolverCount              int
	retryWithDifferentResolver bool
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
	if err != nil {
		// Ignore `Canceled`: resolver lost the race, not an error
		if !errors.Is(err, context.Canceled) {
			r.lastErrorTime.Store(time.Now())
		}

		err = fmt.Errorf("%s: %w", r.resolver, err)
	}

	ch <- requestResponse{
		resolver: &r.resolver,
		response: resp,
		err:      err,
	}
}

type requestResponse struct {
	resolver *Resolver
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
	cfg config.UpstreamGroup, bootstrap *Bootstrap, shouldVerifyUpstreams bool,
) (*ParallelBestResolver, error) {
	logger := log.PrefixedLog(parallelResolverType)

	resolvers, err := createResolvers(logger, cfg, bootstrap, shouldVerifyUpstreams)
	if err != nil {
		return nil, err
	}

	return newParallelBestResolver(cfg, resolvers), nil
}

func newParallelBestResolver(
	cfg config.UpstreamGroup, resolvers []Resolver,
) *ParallelBestResolver {
	resolverStatuses := make([]*upstreamResolverStatus, 0, len(resolvers))

	for _, r := range resolvers {
		resolverStatuses = append(resolverStatuses, newUpstreamResolverStatus(r))
	}

	resolverCount := parallelBestResolverCount
	retryWithDifferentResolver := false

	if config.GetConfig().Upstreams.Strategy == config.UpstreamStrategyRandom {
		resolverCount = 1
		retryWithDifferentResolver = true
	}

	r := ParallelBestResolver{
		configurable: withConfig(&cfg),
		typed:        withType(parallelResolverType),

		groupName: cfg.Name,
		resolvers: resolverStatuses,

		resolverCount:              resolverCount,
		retryWithDifferentResolver: retryWithDifferentResolver,
	}

	return &r
}

func (r *ParallelBestResolver) Name() string {
	return r.String()
}

func (r *ParallelBestResolver) String() string {
	result := make([]string, len(r.resolvers))
	for i, s := range r.resolvers {
		result[i] = fmt.Sprintf("%s", s.resolver)
	}

	return fmt.Sprintf("%s (resolverCount: %d, retryWithDifferentResolver: %t) upstreams '%s (%s)'",
		parallelResolverType, r.resolverCount, r.retryWithDifferentResolver, r.groupName, strings.Join(result, ","))
}

// Resolve sends the query request to multiple upstream resolvers and returns the fastest result
func (r *ParallelBestResolver) Resolve(request *model.Request) (*model.Response, error) {
	logger := log.WithPrefix(request.Log, parallelResolverType)

	if len(r.resolvers) == 1 {
		logger.WithField("resolver", r.resolvers[0].resolver).Debug("delegating to resolver")

		return r.resolvers[0].resolver.Resolve(request)
	}

	ctx := context.Background()

	// using context with timeout for random upstream strategy
	if r.resolverCount == 1 {
		var cancel context.CancelFunc

		logger = log.WithPrefix(logger, "random")
		timeout := config.GetConfig().Upstreams.Timeout

		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout))
		defer cancel()
	}

	resolvers := pickRandom(r.resolvers, r.resolverCount)
	ch := make(chan requestResponse, len(resolvers))

	for _, resolver := range resolvers {
		logger.WithField("resolver", resolver.resolver).Debug("delegating to resolver")

		go resolver.resolve(request, ch)
	}

	response, collectedErrors := evaluateResponses(ctx, logger, ch, resolvers)
	if response != nil {
		return response, nil
	}

	if !r.retryWithDifferentResolver {
		return nil, fmt.Errorf("resolution failed: %w", errors.Join(collectedErrors...))
	}

	return r.retryWithDifferent(logger, request, resolvers)
}

func evaluateResponses(
	ctx context.Context, logger *logrus.Entry, ch chan requestResponse, resolvers []*upstreamResolverStatus,
) (*model.Response, []error) {
	collectedErrors := make([]error, 0, len(resolvers))

	for len(collectedErrors) < len(resolvers) {
		select {
		case <-ctx.Done():
			// this context currently only has a deadline when resolverCount == 1
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				logger.WithField("resolver", resolvers[0].resolver).
					Debug("upstream exceeded timeout, trying other upstream")
				resolvers[0].lastErrorTime.Store(time.Now())
			}
		case result := <-ch:
			if result.err != nil {
				logger.Debug("resolution failed from resolver, cause: ", result.err)
				collectedErrors = append(collectedErrors, fmt.Errorf("resolver: %q error: %w", *result.resolver, result.err))
			} else {
				logger.WithFields(logrus.Fields{
					"resolver": *result.resolver,
					"answer":   util.AnswerToString(result.response.Res.Answer),
				}).Debug("using response from resolver")

				return result.response, nil
			}
		}
	}

	return nil, collectedErrors
}

func (r *ParallelBestResolver) retryWithDifferent(
	logger *logrus.Entry, request *model.Request, resolvers []*upstreamResolverStatus,
) (*model.Response, error) {
	// second try (if retryWithDifferentResolver == true)
	resolver := weightedRandom(r.resolvers, resolvers)
	logger.Debugf("using %s as second resolver", resolver.resolver)

	ch := make(chan requestResponse, 1)

	resolver.resolve(request, ch)

	result := <-ch
	if result.err != nil {
		return nil, fmt.Errorf("resolution retry failed: %w", result.err)
	}

	logger.WithFields(logrus.Fields{
		"resolver": *result.resolver,
		"answer":   util.AnswerToString(result.response.Res.Answer),
	}).Debug("using response from resolver")

	return result.response, nil
}

// pickRandom picks n (resolverCount) different random resolvers from the given resolver pool
func pickRandom(resolvers []*upstreamResolverStatus, resolverCount int) []*upstreamResolverStatus {
	chosenResolvers := make([]*upstreamResolverStatus, 0, resolverCount)

	for i := 0; i < resolverCount; i++ {
		chosenResolvers = append(chosenResolvers, weightedRandom(resolvers, chosenResolvers))
	}

	return chosenResolvers
}

func weightedRandom(in, excludedResolvers []*upstreamResolverStatus) *upstreamResolverStatus {
	const errorWindowInSec = 60

	choices := make([]weightedrand.Choice[*upstreamResolverStatus, uint], 0, len(in))

outer:
	for _, res := range in {
		for _, exclude := range excludedResolvers {
			if exclude.resolver == res.resolver {
				continue outer
			}
		}

		var weight float64 = errorWindowInSec

		if time.Since(res.lastErrorTime.Load().(time.Time)) < time.Hour {
			// reduce weight: consider last error time
			lastErrorTime := res.lastErrorTime.Load().(time.Time)
			weight = math.Max(1, weight-(errorWindowInSec-time.Since(lastErrorTime).Minutes()))
		}

		choices = append(choices, weightedrand.NewChoice(res, uint(weight)))
	}

	c, err := weightedrand.NewChooser(choices...)
	util.LogOnError("can't choose random weighted resolver: ", err)

	return c.Pick()
}
