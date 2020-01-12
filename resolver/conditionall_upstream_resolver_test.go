package resolver

import (
	"blocky/util"
	"testing"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func setup() (sut *ConditionalUpstreamResolver, cond *resolverMock, next *resolverMock) {
	cond = &resolverMock{}
	next = &resolverMock{}
	sut = &ConditionalUpstreamResolver{
		mapping: map[string]Resolver{
			"fritz.box": cond,
			"other.box": cond,
		},
	}

	cond.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
	next.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
	sut.Next(next)

	return
}

func Test_Resolve_Conditional_Exact(t *testing.T) {
	sut, conditionalResolver, nextResolver := setup()

	request := &Request{
		Req: util.NewMsgWithQuestion("fritz.box.", dns.TypeA),
		Log: logrus.NewEntry(logrus.New()),
	}

	resp, err := sut.Resolve(request)
	assert.NoError(t, err)
	assert.Equal(t, "CONDITIONAL", resp.Reason)
	conditionalResolver.AssertExpectations(t)
	nextResolver.AssertNotCalled(t, "Resolve", mock.Anything)
}

func Test_Resolve_Conditional_ExactLast(t *testing.T) {
	sut, conditionalResolver, nextResolver := setup()

	request := &Request{
		Req: util.NewMsgWithQuestion("other.box.", dns.TypeA),
		Log: logrus.NewEntry(logrus.New()),
	}

	resp, err := sut.Resolve(request)
	assert.NoError(t, err)
	assert.Equal(t, "CONDITIONAL", resp.Reason)
	conditionalResolver.AssertExpectations(t)
	nextResolver.AssertNotCalled(t, "Resolve", mock.Anything)
}

func Test_Resolve_Conditional_Subdomain(t *testing.T) {
	sut, conditionalResolver, nextResolver := setup()

	request := &Request{
		Req: util.NewMsgWithQuestion("test.fritz.box.", dns.TypeA),
		Log: logrus.NewEntry(logrus.New()),
	}

	_, err := sut.Resolve(request)
	assert.NoError(t, err)
	conditionalResolver.AssertExpectations(t)
	nextResolver.AssertNotCalled(t, "Resolve", mock.Anything)
}

func Test_Resolve_Conditional_Not_Match(t *testing.T) {
	sut, conditionalResolver, nextResolver := setup()

	request := &Request{
		Req: util.NewMsgWithQuestion("example.com.", dns.TypeA),
		Log: logrus.NewEntry(logrus.New()),
	}

	_, err := sut.Resolve(request)
	assert.NoError(t, err)
	nextResolver.AssertExpectations(t)
	conditionalResolver.AssertNotCalled(t, "Resolve", mock.Anything)
}
