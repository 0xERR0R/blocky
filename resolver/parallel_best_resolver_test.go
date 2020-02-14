package resolver

import (
	"blocky/config"
	"blocky/util"
	"errors"
	"fmt"
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

func Test_Resolve_One_Error(t *testing.T) {
	withError := &resolverMock{}

	withError.On("Resolve", mock.Anything).Return(nil, errors.New("error"))

	mockResp, err := util.NewMsgWithAnswer("example.com. 123 IN A 192.168.178.44")
	if err != nil {
		t.Error(err)
	}

	slow := &resolverMock{}
	slow.On("Resolve", mock.Anything).WaitUntil(time.After(50*time.Millisecond)).Return(&Response{Res: mockResp}, nil)

	sut := NewParallelBestResolver([]Resolver{slow, withError})

	resp, err := sut.Resolve(&Request{
		Req: util.NewMsgWithQuestion("example.com.", dns.TypeA),
		Log: logrus.NewEntry(logrus.New()),
	})

	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Res.Rcode)
	assert.Equal(t, "example.com.	123	IN	A	192.168.178.44", resp.Res.Answer[0].String())
	withError.AssertExpectations(t)
	slow.AssertExpectations(t)
}

func Test_Resolve_All_Error(t *testing.T) {
	withError1 := &resolverMock{}

	withError1.On("Resolve", mock.Anything).Return(nil, errors.New("error"))

	withError2 := &resolverMock{}
	withError2.On("Resolve", mock.Anything).Return(nil, errors.New("error"))

	sut := NewParallelBestResolver([]Resolver{withError1, withError2})

	resp, err := sut.Resolve(&Request{
		Req: util.NewMsgWithQuestion("example.com.", dns.TypeA),
		Log: logrus.NewEntry(logrus.New()),
	})

	assert.Error(t, err)
	assert.Nil(t, resp)
	withError1.AssertExpectations(t)
	withError2.AssertExpectations(t)
}

func Test_Configuration_ParallelResolver(t *testing.T) {
	sut := NewParallelBestResolver([]Resolver{&resolverMock{}, &resolverMock{}})

	c := sut.Configuration()

	assert.Len(t, c, 3)
}

func Test_PickRandom(t *testing.T) {
	sut := NewParallelBestResolver([]Resolver{
		NewUpstreamResolver(config.Upstream{Host: "host1"}),
		NewUpstreamResolver(config.Upstream{Host: "host2"}),
		NewUpstreamResolver(config.Upstream{Host: "host3"})})

	r1, r2 := sut.(*ParallelBestResolver).pickRandom()

	fmt.Println(r1)
	assert.NotEqual(t, r1, r2)
}
