package resolver

import (
	"context"
	"net"
	"testing"

	"github.com/0xERR0R/blocky/model"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type capturingResolver struct {
	Resolver

	got *model.Request
}

func (r *capturingResolver) Type() string   { return "capturing" }
func (r *capturingResolver) String() string { return "capturing" }

func (r *capturingResolver) Resolve(_ context.Context, request *model.Request) (*model.Response, error) {
	r.got = request

	return NoResponse, nil
}

func TestCNAMETargetKeepsClientQueryOptions(t *testing.T) {
	next := &capturingResolver{}
	sut := &CustomDNSResolver{}
	sut.Next(next)

	query := new(dns.Msg)
	query.SetQuestion("alias.example.", dns.TypeA)
	query.CheckingDisabled = true
	query.SetEdns0(1232, true)

	_, err := sut.processCNAME(context.Background(), logrus.NewEntry(logrus.New()),
		&model.Request{Req: query, ClientIP: net.ParseIP("127.0.0.1")},
		dns.CNAME{Target: "target.example."}, nil, query.Question[0], 60)
	if err != nil {
		t.Fatal(err)
	}
	if next.got == nil {
		t.Fatal("the target was not passed to the next resolver")
	}
	if !next.got.Req.CheckingDisabled {
		t.Error("the CD bit was dropped")
	}
	if opt := next.got.Req.IsEdns0(); opt == nil || !opt.Do() {
		t.Errorf("the EDNS0 options were dropped: %v", opt)
	}
}
