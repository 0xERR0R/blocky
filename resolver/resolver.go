package resolver

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"

	"github.com/sirupsen/logrus"
)

func newRequest(question string, rType uint16, logger ...*logrus.Entry) *model.Request {
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

func newRequestWithClient(question string, rType uint16, ip string, clientNames ...string) *model.Request {
	return &model.Request{
		ClientIP:    net.ParseIP(ip),
		ClientNames: clientNames,
		Req:         util.NewMsgWithQuestion(question, rType),
		Log:         logrus.NewEntry(log.Log()),
		RequestTS:   time.Time{},
		Protocol:    model.RequestProtocolUDP,
	}
}

func newRequestWithClientID(question string, rType uint16, ip string, requestClientID string) *model.Request {
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

	// Resolve performs resolution of a DNS request
	Resolve(req *model.Request) (*model.Response, error)

	// Configuration returns current resolver configuration
	Configuration() []string
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

// Name returns a user-friendly name of a resolver
func Name(resolver Resolver) string {
	if named, ok := resolver.(NamedResolver); ok {
		return named.Name()
	}

	return defaultName(resolver)
}

// defaultName returns a short user-friendly name of a resolver
func defaultName(resolver Resolver) string {
	return strings.Split(fmt.Sprintf("%T", resolver), ".")[1]
}

// ChainBuilder is a resolver chain builder
type ChainBuilder struct {
	head, tail ChainedResolver
}

// NewChainBuilder creates a resolver chain builder
// This function returns nil when all given resolvers are nil
func NewChainBuilder(head ChainedResolver, rest ...ChainedResolver) *ChainBuilder {
	newCB := func(head ChainedResolver, rest []ChainedResolver) *ChainBuilder {
		cb := ChainBuilder{
			head: head,
			tail: head,
		}
		cb.Extend(rest)
		return &cb
	}

	if head != nil {
		return newCB(head, rest)
	}

	for i, resolver := range rest {
		if resolver != nil {
			return newCB(resolver, rest[i+1:])
		}
	}

	// All resolvers are nil, not an error: having a valid resolver on End suffices
	return nil
}

// Extend adds all non-nil resolvers to the end of the chain
func (cb *ChainBuilder) Extend(resolvers []ChainedResolver) {
	for _, resolver := range resolvers {
		cb.Next(resolver)
	}
}

// Next adds the resolver to the end of the chain if it is non-nil
func (cb *ChainBuilder) Next(resolver ChainedResolver) {
	if resolver == nil {
		return
	}

	if cb == nil {
		// Panic with nice message instead of dereferencing nil
		panic("called Next on a nil ChainBuilder")
	}

	cb.tail.Next(resolver)
	cb.tail = resolver
}

// End attaches the final resolver and returns the complete chain
// The ChainBuilder should not be reused after calling this
func (cb *ChainBuilder) End(resolver Resolver) (Resolver, error) {
	if resolver == nil {
		return nil, errors.New("cannot end a chain with nil resolver")
	}

	if _, ok := resolver.(ChainedResolver); ok {
		return nil, errors.New("cannot end a chain with a ChainedResolver")
	}

	if cb == nil {
		return resolver, nil
	}

	cb.tail.Next(resolver)

	// Prevent caller from breaking the chain if they reuse `cb`
	head := cb.head
	cb.head = nil
	cb.tail = nil

	return head, nil
}

func logger(prefix string) *logrus.Entry {
	return log.PrefixedLog(prefix)
}

func withPrefix(logger *logrus.Entry, prefix string) *logrus.Entry {
	return logger.WithField("prefix", prefix)
}
