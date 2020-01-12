package resolver

import (
	"net"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type Request struct {
	ClientIP    net.IP
	ClientNames []string
	Req         *dns.Msg
	Log         *logrus.Entry
}

type ResponseType uint8

const (
	Resolved ResponseType = iota
	Blocked
)

type Response struct {
	Res    *dns.Msg
	Reason string
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
