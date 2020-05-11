package resolver

import (
	"blocky/config"
	"blocky/util"
	"fmt"
	"math"
	"time"

	"github.com/mroth/weightedrand"
	"github.com/sirupsen/logrus"
)

// ParallelBestResolver delegates the DNS message to 2 upstream resolvers and returns the fastest answer
type ParallelBestResolver struct {
	resolvers []*upstreamResolverStatus
}

type upstreamResolverStatus struct {
	resolver      Resolver
	lastErrorTime time.Time
}

type requestResponse struct {
	response *Response
	err      error
}

func NewParallelBestResolver(cfg config.UpstreamConfig) Resolver {
	resolvers := make([]*upstreamResolverStatus, len(cfg.ExternalResolvers))

	for i, u := range cfg.ExternalResolvers {
		resolvers[i] = &upstreamResolverStatus{
			resolver:      NewUpstreamResolver(u),
			lastErrorTime: time.Unix(0, 0),
		}
	}

	return &ParallelBestResolver{resolvers: resolvers}
}

func (r *ParallelBestResolver) Configuration() (result []string) {
	result = append(result, "upstream resolvers:")
	for _, res := range r.resolvers {
		result = append(result, fmt.Sprintf("- %s", res.resolver))
	}

	return
}

func (r *ParallelBestResolver) Resolve(request *Request) (*Response, error) {
	logger := request.Log.WithField("prefix", "parallel_best_resolver")

	if len(r.resolvers) == 1 {
		logger.WithField("resolver", r.resolvers[0]).Debug("delegating to resolver")
		return r.resolvers[0].resolver.Resolve(request)
	}

	r1, r2 := r.pickRandom()
	logger.Debugf("using %s and %s as resolver", r1.resolver, r2.resolver)

	ch := make(chan requestResponse, 2)

	var collectedErrors []error

	logger.WithField("resolver", r1).Debug("delegating to resolver")

	go resolve(request, r1, ch)

	logger.WithField("resolver", r2).Debug("delegating to resolver")

	go resolve(request, r2, ch)

	//nolint: gosimple
	for len(collectedErrors) < 2 {
		select {
		case result := <-ch:
			if result.err != nil {
				logger.Debug("resolution failed from resolver, cause: ", result.err)
				collectedErrors = append(collectedErrors, result.err)
			} else {
				logger.WithFields(logrus.Fields{
					"resolver": r1,
					"answer":   util.AnswerToString(result.response.Res.Answer),
				}).Debug("using response from resolver")
				return result.response, nil
			}
		}
	}

	return nil, fmt.Errorf("resolution was not successful, errors: %v", collectedErrors)
}

// pick 2 different random resolvers from the resolver pool
func (r *ParallelBestResolver) pickRandom() (resolver1, resolver2 *upstreamResolverStatus) {
	resolver1 = weightedRandom(r.resolvers, nil)
	resolver2 = weightedRandom(r.resolvers, resolver1.resolver)

	return
}

func weightedRandom(in []*upstreamResolverStatus, exclude Resolver) *upstreamResolverStatus {
	var choices []weightedrand.Choice

	for _, res := range in {
		var weight float64 = 60

		if time.Since(res.lastErrorTime) < time.Hour {
			// reduce weight: consider last error time
			weight = math.Max(1, weight-(60-time.Since(res.lastErrorTime).Minutes()))
		}

		if exclude != res.resolver {
			choices = append(choices, weightedrand.Choice{
				Item:   res,
				Weight: uint(weight),
			})
		}
	}

	c := weightedrand.NewChooser(choices...)

	return c.Pick().(*upstreamResolverStatus)
}

func resolve(req *Request, resolver *upstreamResolverStatus, ch chan<- requestResponse) {
	resp, err := resolver.resolver.Resolve(req)

	// update the last error time
	if err != nil {
		resolver.lastErrorTime = time.Now()
	}
	ch <- requestResponse{
		response: resp,
		err:      err,
	}
}
