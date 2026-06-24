package resolver

import (
	"context"
	"log/slog"

	"github.com/0xERR0R/blocky/model"
)

var NoResponse = &model.Response{} //nolint:gochecknoglobals

// NoOpResolver is used to finish a resolver branch as created in RewriterResolver
type NoOpResolver struct{}

func NewNoOpResolver() *NoOpResolver {
	return &NoOpResolver{}
}

// Type implements `Resolver`.
func (NoOpResolver) Type() string {
	return "noop"
}

// String implements `fmt.Stringer`.
func (r NoOpResolver) String() string {
	return r.Type()
}

// IsEnabled implements `config.Configurable`.
func (NoOpResolver) IsEnabled() bool {
	return true
}

// LogConfig implements `config.Configurable`.
func (NoOpResolver) LogConfig(*slog.Logger) {
}

func (NoOpResolver) Resolve(context.Context, *model.Request) (*model.Response, error) {
	return NoResponse, nil
}
