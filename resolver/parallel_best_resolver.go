package resolver

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"sync/atomic"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"

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

	resolvers atomic.Pointer[[]*upstreamResolverStatus]

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

func newUpstreamResolverStatuses(resolvers []Resolver) []*upstreamResolverStatus {
	statuses := make([]*upstreamResolverStatus, 0, len(resolvers))

	for _, r := range resolvers {
		statuses = append(statuses, newUpstreamResolverStatus(r))
	}

	return statuses
}

func (r *upstreamResolverStatus) resolve(ctx context.Context, req *model.Request) (*model.Response, error) {
	resp, err := r.resolver.Resolve(ctx, req)
	if err != nil {
		// Ignore `Canceled`: resolver lost the race, not an error
		if !errors.Is(err, context.Canceled) {
			r.lastErrorTime.Store(time.Now())
		}

		return nil, fmt.Errorf("%s: %w", r.resolver, err)
	}

	return resp, nil
}

func (r *upstreamResolverStatus) resolveToChan(ctx context.Context, req *model.Request, ch chan<- requestResponse) {
	resp, err := r.resolve(ctx, req)

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

// NewParallelBestResolver creates new resolver instance
func NewParallelBestResolver(
	ctx context.Context, cfg config.UpstreamGroup, bootstrap *Bootstrap,
) (*ParallelBestResolver, error) {
	r := newParallelBestResolver(
		cfg,
		[]Resolver{bootstrap}, // if init strategy is fast, use bootstrap until init finishes
	)

	return initGroupResolvers(ctx, r, cfg, bootstrap)
}

func newParallelBestResolver(cfg config.UpstreamGroup, resolvers []Resolver) *ParallelBestResolver {
	typeName := "parallel_best"
	resolverCount := parallelBestResolverCount
	retryWithDifferentResolver := false

	if cfg.Strategy == config.UpstreamStrategyRandom {
		typeName = "random"
		resolverCount = 1
		retryWithDifferentResolver = true
	}

	r := ParallelBestResolver{
		configurable: withConfig(&cfg),
		typed:        withType(typeName),

		resolverCount:              resolverCount,
		retryWithDifferentResolver: retryWithDifferentResolver,
	}

	r.setResolvers(newUpstreamResolverStatuses(resolvers))

	return &r
}

func (r *ParallelBestResolver) setResolvers(resolvers []*upstreamResolverStatus) {
	r.resolvers.Store(&resolvers)
}

func (r *ParallelBestResolver) Name() string {
	return r.String()
}

func (r *ParallelBestResolver) String() string {
	resolvers := *r.resolvers.Load()

	upstreams := make([]string, len(resolvers))
	for i, s := range resolvers {
		upstreams[i] = s.resolver.String()
	}

	return fmt.Sprintf("%s upstreams '%s (%s)'", r.Type(), r.cfg.Name, strings.Join(upstreams, ","))
}

// Resolve sends the query request to multiple upstream resolvers and returns the fastest result
func (r *ParallelBestResolver) Resolve(ctx context.Context, request *model.Request) (*model.Response, error) {
	ctx, logger := r.log(ctx)

	allResolvers := *r.resolvers.Load()

	if len(allResolvers) == 1 {
		resolver := allResolvers[0]
		logger.WithField("resolver", resolver.resolver).Debug("delegating to resolver")

		return resolver.resolve(ctx, request)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // abort requests to resolvers that lost the race

	resolvers := pickRandom(ctx, allResolvers, r.resolverCount)
	ch := make(chan requestResponse, len(resolvers))

	for _, resolver := range resolvers {
		logger.WithField("resolver", resolver.resolver).Debug("delegating to resolver")

		go resolver.resolveToChan(ctx, request, ch)
	}

	response, collectedErrors := evaluateResponses(logger, ch, resolvers)
	if response != nil {
		return response, nil
	}

	if !r.retryWithDifferentResolver {
		return nil, fmt.Errorf("resolution failed: %w", errors.Join(collectedErrors...))
	}

	return r.retryWithDifferent(ctx, logger, request, resolvers)
}

func evaluateResponses(
	logger *logrus.Entry, ch chan requestResponse, resolvers []*upstreamResolverStatus,
) (*model.Response, []error) {
	collectedErrors := make([]error, 0, len(resolvers))

	for len(collectedErrors) < len(resolvers) {
		result := <-ch
		logger := logger.WithField("resolver", *result.resolver)

		if result.err != nil {
			logger.Debug("resolution failed from resolver, cause: ", result.err)
			collectedErrors = append(collectedErrors, fmt.Errorf("resolver: %q error: %w", *result.resolver, result.err))

			continue
		}

		logger.WithField("answer", util.AnswerToString(result.response.Res.Answer)).Debug("using response from resolver")

		return result.response, nil
	}

	return nil, collectedErrors
}

func (r *ParallelBestResolver) retryWithDifferent(
	ctx context.Context, logger *logrus.Entry, request *model.Request, resolvers []*upstreamResolverStatus,
) (*model.Response, error) {
	// second try (if retryWithDifferentResolver == true)
	resolver := weightedRandom(ctx, *r.resolvers.Load(), resolvers)
	logger.Debugf("using %s as second resolver", resolver.resolver)

	resp, err := resolver.resolve(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("resolution retry failed: %w", err)
	}

	logger.WithFields(logrus.Fields{
		"resolver": *resolver,
		"answer":   util.AnswerToString(resp.Res.Answer),
	}).Debug("using response from resolver")

	return resp, nil
}

// pickRandom picks n (resolverCount) different random resolvers from the given resolver pool
func pickRandom(ctx context.Context, resolvers []*upstreamResolverStatus, resolverCount int) []*upstreamResolverStatus {
	chosenResolvers := make([]*upstreamResolverStatus, 0, resolverCount)

	for i := 0; i < resolverCount; i++ {
		chosenResolvers = append(chosenResolvers, weightedRandom(ctx, resolvers, chosenResolvers))
	}

	return chosenResolvers
}

func weightedRandom(ctx context.Context, in, excludedResolvers []*upstreamResolverStatus) *upstreamResolverStatus {
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
	if err != nil {
		log.FromCtx(ctx).WithError(err).Error("can't choose random weighted resolver, falling back to uniform random")

		val := rand.Int() //nolint:gosec // pseudo-randomness is good enough

		return choices[val%len(choices)].Item
	}

	return c.Pick()
}
