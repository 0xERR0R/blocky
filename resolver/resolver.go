package resolver

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type Request struct {
	ClientIP    net.IP
	ClientNames []string
	Req         *dns.Msg
	Log         *logrus.Entry
}

type ResponseType int

const (
	RESOLVED ResponseType = iota
	CACHED
	BLOCKED
	CONDITIONAL
	CUSTOMDNS
)

type Response struct {
	Res    *dns.Msg
	Reason string
	rType  ResponseType
}
type Resolver interface {
	Resolve(req *Request) (*Response, error)
	Configuration() []string
}

type ChainedResolver interface {
	Resolver
	Next(n Resolver)
	GetNext() Resolver
}

type NextResolver struct {
	next Resolver
}

func (r *NextResolver) Next(n Resolver) {
	r.next = n
}

func (r *NextResolver) GetNext() Resolver {
	return r.next
}

func logger(prefix string) *logrus.Entry {
	return logrus.WithField("prefix", prefix)
}

func withPrefix(logger *logrus.Entry, prefix string) *logrus.Entry {
	return logger.WithField("prefix", prefix)
}

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

func Name(resolver Resolver) string {
	return strings.Split(fmt.Sprintf("%T", resolver), ".")[1]
}
