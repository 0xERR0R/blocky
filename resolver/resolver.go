//go:generate go run github.com/abice/go-enum -f=$GOFILE --marshal --names
package resolver

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"

	"github.com/sirupsen/logrus"
)

// Resolver is not configured.
const (
	configStatusEnabled string = "enabled"

	configStatusDisabled string = "disabled"
)

var (
	// note: this is not used by all resolvers: only those that don't print any other configuration
	configEnabled = []string{configStatusEnabled} //nolint:gochecknoglobals

	configDisabled = []string{configStatusDisabled} //nolint:gochecknoglobals
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

// newResponseMsg creates a new dns.Msg as response for a request
func newResponseMsg(request *model.Request) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(request.Req)

	return response
}

// returnResponseModel wrapps a dns.Msg into a model.Response
func returnResponseModel(response *dns.Msg, rtype model.ResponseType, reason string) (*model.Response, error) {
	return &model.Response{
		Res:    response,
		RType:  rtype,
		Reason: reason,
	}, nil
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

	return defaultName(resolver)
}

// defaultName returns a short user-friendly name of a resolver
func defaultName(resolver Resolver) string {
	return strings.Split(fmt.Sprintf("%T", resolver), ".")[1]
}
