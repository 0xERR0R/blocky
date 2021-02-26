package resolver

import (
	"blocky/log"
	"blocky/util"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// RequestProtocol represents the server protocol
type RequestProtocol uint8

const (
	// TCP is the TPC protocol
	TCP RequestProtocol = iota

	// UDP is the UDP protocol
	UDP
)

func (r RequestProtocol) String() string {
	names := [...]string{
		"TCP",
		"UDP"}

	return names[r]
}

// Request represents client's DNS request
type Request struct {
	ClientIP    net.IP
	Protocol    RequestProtocol
	ClientNames []string
	Req         *dns.Msg
	Log         *logrus.Entry
	RequestTS   time.Time
}

func newRequest(question string, rType uint16, logger ...*logrus.Entry) *Request {
	var loggerEntry *logrus.Entry
	if len(logger) == 1 {
		loggerEntry = logger[0]
	} else {
		loggerEntry = logrus.NewEntry(log.Log())
	}

	return &Request{
		Req:      util.NewMsgWithQuestion(question, rType),
		Log:      loggerEntry,
		Protocol: UDP,
	}
}

func newRequestWithClient(question string, rType uint16, ip string, clientNames ...string) *Request {
	return &Request{
		ClientIP:    net.ParseIP(ip),
		ClientNames: clientNames,
		Req:         util.NewMsgWithQuestion(question, rType),
		Log:         logrus.NewEntry(log.Log()),
		RequestTS:   time.Time{},
		Protocol:    UDP,
	}
}

// ResponseType represents the type of the response
type ResponseType int

const (
	// RESOLVED the response was resolved by the external upstream resolver
	RESOLVED ResponseType = iota

	// CACHED the response was resolved from cache
	CACHED

	// BLOCKED the query was blocked
	BLOCKED

	// CONDITIONAL the query was resolved by the conditional upstream resolver
	CONDITIONAL

	// CUSTOMDNS the query was resolved by a custom rule
	CUSTOMDNS
)

func (r ResponseType) String() string {
	names := [...]string{
		"RESOLVED",
		"CACHED",
		"BLOCKED",
		"CONDITIONAL",
		"CUSTOMDNS"}

	return names[r]
}

// Response represents the response of a DNS query
type Response struct {
	Res    *dns.Msg
	Reason string
	RType  ResponseType
}

// Resolver generic interface for all resolvers
type Resolver interface {

	// Resolve performs resolution of a DNS request
	Resolve(req *Request) (*Response, error)

	// Configuration prints current resolver configuration
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

func logger(prefix string) *logrus.Entry {
	return log.PrefixedLog(prefix)
}

func withPrefix(logger *logrus.Entry, prefix string) *logrus.Entry {
	return logger.WithField("prefix", prefix)
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
	return strings.Split(fmt.Sprintf("%T", resolver), ".")[1]
}
