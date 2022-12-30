package resolver

import (
	"github.com/0xERR0R/blocky/model"
)

var NoResponse = &model.Response{} //nolint:gochecknoglobals

// NoOpResolver is used to finish a resolver branch as created in RewriterResolver
type NoOpResolver struct{}

func NewNoOpResolver() Resolver {
	return NoOpResolver{}
}

func (r NoOpResolver) Configuration() (result []string) {
	return nil
}

func (r NoOpResolver) Resolve(request *model.Request) (*model.Response, error) {
	return NoResponse, nil
}
