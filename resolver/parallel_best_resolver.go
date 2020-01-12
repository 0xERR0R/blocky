package resolver

import (
	"blocky/util"
	"fmt"
	"math/rand"

	"github.com/sirupsen/logrus"
)

// ParallelBestResolver delegates the DNS message to 2 upstream resolvers and returns the fastest answer
type ParallelBestResolver struct {
	resolvers []Resolver
}

func NewParallelBestResolver(resolvers []Resolver) Resolver {
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

	r1, r2 := r.pickRandom()
	logger.Debugf("using %s and %s as resolver", r1, r2)

	ch1 := make(chan struct {
		*Response
		error
	})
	ch2 := make(chan struct {
		*Response
		error
	})

	var err1, err2 error

	logger.WithField("resolver", r1).Debug("delegating to resolver")

	go resolve(request, r1, ch1)

	logger.WithField("resolver", r2).Debug("delegating to resolver")

	go resolve(request, r2, ch2)

	for err1 == nil || err2 == nil {
		select {
		case msg1 := <-ch1:
			if msg1.error != nil {
				err1 = msg1.error
				ch1 = nil

				logger.WithField("resolver", r1).Debug("resolution failed from resolver, cause: ", msg1.error)
			} else {
				logger.WithFields(logrus.Fields{
					"resolver": r1,
					"answer":   util.AnswerToString(msg1.Response.Res.Answer),
				}).Debug("using response from resolver")
				return msg1.Response, nil
			}
		case msg2 := <-ch2:
			if msg2.error != nil {
				err2 = msg2.error
				ch2 = nil

				logger.WithField("resolver", r2).Debug("resolution failed from resolver, cause: ", msg2.error)
			} else {
				logger.WithFields(logrus.Fields{
					"resolver": r2,
					"answer":   util.AnswerToString(msg2.Response.Res.Answer),
				}).Debug("using response from resolver")
				return msg2.Response, nil
			}
		}
	}

	return nil, fmt.Errorf("resolution was not successful, errors: '%v', '%v'", err1, err2)
}

// pick 2 different random resolvers from the resolver pool
func (r *ParallelBestResolver) pickRandom() (resolver1, resolver2 Resolver) {
	resolver1 = r.resolvers[rand.Intn(len(r.resolvers))]
	for resolver2 == resolver1 || resolver2 == nil {
		resolver2 = r.resolvers[rand.Intn(len(r.resolvers))]
	}

	return
}

func resolve(req *Request, resolver Resolver, ch chan struct {
	*Response
	error
}) {
	defer close(ch)

	resp, err := resolver.Resolve(req)
	ch <- struct {
		*Response
		error
	}{resp, err}
}

func (r ParallelBestResolver) String() string {
	return fmt.Sprintf("parallel best resolver '%s'", r.resolvers)
}
