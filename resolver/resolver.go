package resolver

import (
	"blocky/util"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type Request struct {
	ClientIP    net.IP
	ClientNames []string
	Req         *dns.Msg
	Log         *logrus.Entry
	RequestTS   time.Time
}

func newRequest(question string, rType uint16) *Request {
	return &Request{
		Req: util.NewMsgWithQuestion(question, rType),
		Log: logrus.NewEntry(logrus.New()),
	}
}

func newRequestWithClient(question string, rType uint16, ip string, clientNames ...string) *Request {
	return &Request{
		ClientIP:    net.ParseIP(ip),
		ClientNames: clientNames,
		Req:         util.NewMsgWithQuestion(question, rType),
		Log:         logrus.NewEntry(logrus.New()),
		RequestTS:   time.Time{},
	}
}

type ResponseType int

const (
	RESOLVED ResponseType = iota
	CACHED
	BLOCKED
	CONDITIONAL
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

type Response struct {
	Res    *dns.Msg
	Reason string
	RType  ResponseType
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
