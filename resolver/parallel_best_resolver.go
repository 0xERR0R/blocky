package resolver

import (
	"blocky/config"
	"blocky/util"
	"fmt"
	"math/rand"

	"github.com/sirupsen/logrus"
)

// ParallelBestResolver delegates the DNS message to 2 upstream resolvers and returns the fastest answer
type ParallelBestResolver struct {
	resolvers []Resolver
}

type requestResponse struct {
	response *Response
	err      error
}

func NewParallelBestResolver(cfg config.UpstreamConfig) Resolver {
	resolvers := make([]Resolver, len(cfg.ExternalResolvers))

	for i, u := range cfg.ExternalResolvers {
		resolvers[i] = NewUpstreamResolver(u)
	}

	return &ParallelBestResolver{resolvers: resolvers}
}

func (r *ParallelBestResolver) Configuration() (result []string) {
	result = append(result, "upstream resolvers:")
	for _, res := range r.resolvers {
		result = append(result, fmt.Sprintf("- %s", res))
	}

	return
}

func (r *ParallelBestResolver) Resolve(request *Request) (*Response, error) {
	logger := request.Log.WithField("prefix", "parallel_best_resolver")

	if len(r.resolvers) == 1 {
		logger.WithField("resolver", r.resolvers[0]).Debug("delegating to resolver")
		return r.resolvers[0].Resolve(request)
	}

	r1, r2 := r.pickRandom()
	logger.Debugf("using %s and %s as resolver", r1, r2)

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
func (r *ParallelBestResolver) pickRandom() (resolver1, resolver2 Resolver) {
	randomInd := rand.Perm(len(r.resolvers))

	return r.resolvers[randomInd[0]], r.resolvers[randomInd[1]]
}

func resolve(req *Request, resolver Resolver, ch chan<- requestResponse) {
	resp, err := resolver.Resolve(req)
	ch <- requestResponse{
		response: resp,
		err:      err,
	}
}
