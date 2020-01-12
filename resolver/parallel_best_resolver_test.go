package resolver

import (
	"blocky/util"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func Test_Resolve_Best_Result(t *testing.T) {
	fast := &resolverMock{}

	mockResp, err := util.NewMsgWithAnswer("example.com. 123 IN A 192.168.178.44")
	if err != nil {
		t.Error(err)
	}

	fast.On("Resolve", mock.Anything).Return(&Response{Res: mockResp}, nil)

	slow := &resolverMock{}
	slow.On("Resolve", mock.Anything).WaitUntil(time.After(50*time.Millisecond)).Return(&Response{Res: new(dns.Msg)}, nil)

	sut := NewParallelBestResolver([]Resolver{slow, fast})

	resp, err := sut.Resolve(&Request{
		Req: util.NewMsgWithQuestion("example.com.", dns.TypeA),
		Log: logrus.NewEntry(logrus.New()),
	})

	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Res.Rcode)
	assert.Equal(t, "example.com.	123	IN	A	192.168.178.44", resp.Res.Answer[0].String())
	fast.AssertExpectations(t)
	slow.AssertExpectations(t)
}
