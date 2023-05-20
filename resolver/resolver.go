package resolver

import (
	"net"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"

	"github.com/sirupsen/logrus"
)

func newRequest(question string, rType dns.Type, logger ...*logrus.Entry) *model.Request {
	var loggerEntry *logrus.Entry
	if len(logger) == 1 {
		loggerEntry = logger[0]
	} else {
		loggerEntry = logrus.NewEntry(log.Log())
	}

	return &model.Request{
		Req:      util.NewMsgWithQuestion(question, rType),
		Log:      loggerEntry,
		Protocol: model.RequestProtocolUDP,
	}
}

func newRequestWithClient(question string, rType dns.Type, ip string, clientNames ...string) *model.Request {
	return &model.Request{
		ClientIP:    net.ParseIP(ip),
		ClientNames: clientNames,
		Req:         util.NewMsgWithQuestion(question, rType),
		Log:         logrus.NewEntry(log.Log()),
		RequestTS:   time.Time{},
		Protocol:    model.RequestProtocolUDP,
	}
}

// newResponse creates a response to the given request
func newResponse(request *model.Request, rcode int, rtype model.ResponseType, reason string) *model.Response {
	response := new(dns.Msg)
	response.SetReply(request.Req)
	response.Rcode = rcode

	return &model.Response{
		Res:    response,
		RType:  rtype,
		Reason: reason,
	}
}

func newRequestWithClientID(question string, rType dns.Type, ip, requestClientID string) *model.Request {
	return &model.Request{
		ClientIP:        net.ParseIP(ip),
		RequestClientID: requestClientID,
		Req:             util.NewMsgWithQuestion(question, rType),
		Log:             logrus.NewEntry(log.Log()),
		RequestTS:       time.Time{},
		Protocol:        model.RequestProtocolUDP,
	}
}

// Resolver generic interface for all resolvers
type Resolver interface {
	config.Configurable

	// Type returns a short, user-friendly, name for the resolver.
	//
	// It should be the same for all instances of a specific Resolver type.
	Type() string

	// Resolve performs resolution of a DNS request
	Resolve(req *model.Request) (*model.Response, error)
}

// ChainedResolver represents a resolver, which can delegate result to the next one
type ChainedResolver interface {
	Resolver

	// Next sets the next resolver
	Next(n Resolver)

	// GetNext returns the next resolver
	GetNext() Resolver
}

// NextResolver is the base implementation of ChainedResolver
type NextResolver struct {
	next Resolver
}

// Next sets the next resolver
func (r *NextResolver) Next(n Resolver) {
	r.next = n
}

// GetNext returns the next resolver
func (r *NextResolver) GetNext() Resolver {
	return r.next
}

// NamedResolver is a resolver with a special name
type NamedResolver interface {
	// Name returns the full name of the resolver
	Name() string
}

// Chain creates a chain of resolvers
func Chain(resolvers ...Resolver) Resolver {
	for i, res := range resolvers {
		if i+1 < len(resolvers) {
			if cr, ok := res.(ChainedResolver); ok {
				cr.Next(resolvers[i+1])
			}
		}
	}

	return resolvers[0]
}

// Name returns a user-friendly name of a resolver
func Name(resolver Resolver) string {
	if named, ok := resolver.(NamedResolver); ok {
		return named.Name()
	}

	return resolver.Type()
}

// ForEach iterates over all resolvers in the chain.
//
// If resolver is not a chain, or is unlinked,
// the callback is called exactly once.
func ForEach(resolver Resolver, callback func(Resolver)) {
	for resolver != nil {
		callback(resolver)

		if chained, ok := resolver.(ChainedResolver); ok {
			resolver = chained.GetNext()
		} else {
			break
		}
	}
}

// LogResolverConfig logs the resolver's type and config.
func LogResolverConfig(res Resolver, logger *logrus.Entry) {
	// Use the type, not the full typeName, to avoid redundant information with the config
	typeName := res.Type()

	if !res.IsEnabled() {
		logger.Debugf("-> %s: disabled", typeName)

		return
	}

	logger.Infof("-> %s:", typeName)
	log.WithIndent(logger, "     ", res.LogConfig)
}

// Should be embedded in a Resolver to auto-implement `Resolver.Type`.
type typed struct {
	typeName string
}

func withType(t string) typed {
	return typed{typeName: t}
}

// Type implements `Resolver`.
func (t *typed) Type() string {
	return t.typeName
}

func (t *typed) log() *logrus.Entry {
	return log.PrefixedLog(t.Type())
}

// Should be embedded in a Resolver to auto-implement `config.Configurable`.
type configurable[T config.Configurable] struct {
	cfg T
}

func withConfig[T config.Configurable](cfg T) configurable[T] {
	return configurable[T]{cfg: cfg}
}

// IsEnabled implements `config.Configurable`.
func (c *configurable[T]) IsEnabled() bool {
	return c.cfg.IsEnabled()
}

// LogConfig implements `config.Configurable`.
func (c *configurable[T]) LogConfig(logger *logrus.Entry) {
	c.cfg.LogConfig(logger)
}
