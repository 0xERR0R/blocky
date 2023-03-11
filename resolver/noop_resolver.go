package resolver

import (
	"github.com/0xERR0R/blocky/model"
	"github.com/sirupsen/logrus"
)

var NoResponse = &model.Response{} //nolint:gochecknoglobals

// NoOpResolver is used to finish a resolver branch as created in RewriterResolver
type NoOpResolver struct{}

func NewNoOpResolver() Resolver {
	return NoOpResolver{}
}

// IsEnabled implements `config.ValueLogger`.
func (NoOpResolver) IsEnabled() bool {
	return true
}

// LogValues implements `config.ValueLogger`.
func (NoOpResolver) LogValues(*logrus.Entry) {
}

func (NoOpResolver) Resolve(*model.Request) (*model.Response, error) {
	return NoResponse, nil
}
