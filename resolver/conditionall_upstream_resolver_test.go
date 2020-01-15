package resolver

import (
	"blocky/config"
	"blocky/util"
	"fmt"
	"testing"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func setup() (sut ChainedResolver, next *resolverMock) {
	sut = NewConditionalUpstreamResolver(config.ConditionalUpstreamConfig{
		Mapping: map[string]config.Upstream{
			"fritz.box": TestUDPUpstream(func(request *dns.Msg) (response *dns.Msg) {
				response, _ = util.NewMsgWithAnswer(fmt.Sprintf("%s 123 IN A 123.124.122.122", request.Question[0].Name))

				return response
			}),
			"other.box": TestUDPUpstream(func(request *dns.Msg) (response *dns.Msg) {
				response, _ = util.NewMsgWithAnswer(fmt.Sprintf("%s 250 IN A 192.192.192.192", request.Question[0].Name))

				return response
			}),
		},
	})

	next = &resolverMock{}

	next.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
	sut.Next(next)

	return
}

func Test_Resolve_Conditional_Exact(t *testing.T) {
	sut, nextResolver := setup()
	request := &Request{
		Req: util.NewMsgWithQuestion("fritz.box.", dns.TypeA),
		Log: logrus.NewEntry(logrus.New()),
	}

	resp, err := sut.Resolve(request)
	assert.NoError(t, err)
	assert.Equal(t, "CONDITIONAL", resp.Reason)
	assert.Equal(t, dns.RcodeSuccess, resp.Res.Rcode)
	assert.Equal(t, "fritz.box.	123	IN	A	123.124.122.122", resp.Res.Answer[0].String())
	nextResolver.AssertNotCalled(t, "Resolve", mock.Anything)
}

func Test_Resolve_Conditional_ExactLast(t *testing.T) {
	sut, nextResolver := setup()

	request := &Request{
		Req: util.NewMsgWithQuestion("other.box.", dns.TypeA),
		Log: logrus.NewEntry(logrus.New()),
	}

	resp, err := sut.Resolve(request)
	assert.NoError(t, err)
	assert.Equal(t, "CONDITIONAL", resp.Reason)
	assert.Equal(t, "other.box.	250	IN	A	192.192.192.192", resp.Res.Answer[0].String())
	nextResolver.AssertNotCalled(t, "Resolve", mock.Anything)
}

func Test_Resolve_Conditional_Subdomain(t *testing.T) {
	sut, nextResolver := setup()

	request := &Request{
		Req: util.NewMsgWithQuestion("test.fritz.box.", dns.TypeA),
		Log: logrus.NewEntry(logrus.New()),
	}

	resp, err := sut.Resolve(request)
	assert.NoError(t, err)
	assert.Equal(t, "test.fritz.box.	123	IN	A	123.124.122.122", resp.Res.Answer[0].String())
	nextResolver.AssertNotCalled(t, "Resolve", mock.Anything)
}

func Test_Resolve_Conditional_Not_Match(t *testing.T) {
	sut, nextResolver := setup()

	request := &Request{
		Req: util.NewMsgWithQuestion("example.com.", dns.TypeA),
		Log: logrus.NewEntry(logrus.New()),
	}

	_, err := sut.Resolve(request)
	assert.NoError(t, err)
	nextResolver.AssertExpectations(t)
}

func Test_Configuration_ConditionalResolver_WithConfig(t *testing.T) {
	sut, _ := setup()
	c := sut.Configuration()
	assert.Len(t, c, 2)
}

func Test_Configuration_ConditionalResolver_Disabled(t *testing.T) {
	sut := NewConditionalUpstreamResolver(config.ConditionalUpstreamConfig{})
	c := sut.Configuration()
	assert.Equal(t, []string{"deactivated"}, c)
}
