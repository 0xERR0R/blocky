package resolver

import (
	"blocky/config"
	"blocky/util"
	"fmt"
	"net"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestClientNamesFromUpstream(t *testing.T) {
	callCount := 0
	upstream := TestUDPUpstream(func(request *dns.Msg) *dns.Msg {
		callCount++
		r, err := dns.ReverseAddr("192.168.178.25")
		assert.NoError(t, err)

		response, err := util.NewMsgWithAnswer(fmt.Sprintf("%s 300 IN PTR myhost", r))

		assert.NoError(t, err)
		return response
	})

	sut := NewClientNamesResolver(config.ClientLookupConfig{Upstream: upstream})
	m := &resolverMock{}
	m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
	sut.Next(m)

	// first request
	request := &Request{
		ClientIP: net.ParseIP("192.168.178.25"),
		Log:      logrus.NewEntry(logrus.New())}
	_, err := sut.Resolve(request)

	assert.Equal(t, 1, callCount)

	m.AssertExpectations(t)
	assert.NoError(t, err)
	assert.Equal(t, "myhost", request.ClientNames[0])

	// second request
	request = &Request{ClientIP: net.ParseIP("192.168.178.25"),
		Log: logrus.NewEntry(logrus.New())}
	_, err = sut.Resolve(request)

	// use cache -> call count 1
	assert.Equal(t, 1, callCount)

	m.AssertExpectations(t)
	assert.NoError(t, err)
	assert.Len(t, request.ClientNames, 1)
	assert.Equal(t, "myhost", request.ClientNames[0])
}

func TestClientInfoFromUpstreamSingleNameWithOrder(t *testing.T) {
	var callCount int32

	upstream := TestUDPUpstream(func(request *dns.Msg) *dns.Msg {
		atomic.AddInt32(&callCount, 1)
		r, err := dns.ReverseAddr("192.168.178.25")
		assert.NoError(t, err)

		response, err := util.NewMsgWithAnswer(fmt.Sprintf("%s 300 IN PTR myhost", r))

		assert.NoError(t, err)
		return response
	})

	sut := NewClientNamesResolver(config.ClientLookupConfig{
		Upstream:        upstream,
		SingleNameOrder: []uint{2, 1}})
	m := &resolverMock{}
	m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
	sut.Next(m)

	// first request
	request := &Request{
		ClientIP: net.ParseIP("192.168.178.25"),
		Log:      logrus.NewEntry(logrus.New())}
	_, err := sut.Resolve(request)

	assert.Equal(t, int32(1), callCount)

	m.AssertExpectations(t)
	assert.NoError(t, err)
	assert.Equal(t, "myhost", request.ClientNames[0])

	// second request
	request = &Request{ClientIP: net.ParseIP("192.168.178.25"),
		Log: logrus.NewEntry(logrus.New())}
	_, err = sut.Resolve(request)

	// use cache -> call count 1
	assert.Equal(t, int32(1), callCount)

	m.AssertExpectations(t)
	assert.NoError(t, err)
	assert.Len(t, request.ClientNames, 1)
	assert.Equal(t, "myhost", request.ClientNames[0])
}

func TestClientInfoFromUpstreamMultipleNames(t *testing.T) {
	upstream := TestUDPUpstream(func(request *dns.Msg) *dns.Msg {
		r, err := dns.ReverseAddr("192.168.178.25")
		assert.NoError(t, err)

		rr1, err := dns.NewRR(fmt.Sprintf("%s 300 IN PTR myhost1", r))
		assert.NoError(t, err)
		rr2, err := dns.NewRR(fmt.Sprintf("%s 300 IN PTR myhost2", r))
		assert.NoError(t, err)

		msg := new(dns.Msg)
		msg.Answer = []dns.RR{rr1, rr2}

		return msg
	})

	sut := NewClientNamesResolver(config.ClientLookupConfig{Upstream: upstream})
	m := &resolverMock{}
	m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
	sut.Next(m)

	request := &Request{
		ClientIP: net.ParseIP("192.168.178.25"),
		Log:      logrus.NewEntry(logrus.New())}
	_, err := sut.Resolve(request)

	m.AssertExpectations(t)
	assert.NoError(t, err)
	assert.Len(t, request.ClientNames, 2)
	assert.Equal(t, "myhost1", request.ClientNames[0])
	assert.Equal(t, "myhost2", request.ClientNames[1])
}

func TestClientInfoFromUpstreamMultipleNamesSingleNameOrder(t *testing.T) {
	upstream := TestUDPUpstream(func(request *dns.Msg) *dns.Msg {
		r, err := dns.ReverseAddr("192.168.178.25")
		assert.NoError(t, err)

		rr1, err := dns.NewRR(fmt.Sprintf("%s 300 IN PTR myhost1", r))
		assert.NoError(t, err)
		rr2, err := dns.NewRR(fmt.Sprintf("%s 300 IN PTR myhost2", r))
		assert.NoError(t, err)

		msg := new(dns.Msg)
		msg.Answer = []dns.RR{rr1, rr2}

		return msg
	})

	sut := NewClientNamesResolver(config.ClientLookupConfig{
		Upstream:        upstream,
		SingleNameOrder: []uint{2, 1}})
	m := &resolverMock{}
	m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
	sut.Next(m)

	request := &Request{
		ClientIP: net.ParseIP("192.168.178.25"),
		Log:      logrus.NewEntry(logrus.New())}
	_, err := sut.Resolve(request)

	m.AssertExpectations(t)
	assert.NoError(t, err)
	assert.Len(t, request.ClientNames, 1)
	assert.Equal(t, "myhost2", request.ClientNames[0])
}

func TestClientInfoFromUpstreamNotFound(t *testing.T) {
	upstream := TestUDPUpstream(func(request *dns.Msg) *dns.Msg {
		msg := new(dns.Msg)
		msg.SetRcode(request, dns.RcodeNameError)

		return msg
	})

	sut := NewClientNamesResolver(config.ClientLookupConfig{Upstream: upstream})
	m := &resolverMock{}
	m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
	sut.Next(m)

	request := &Request{ClientIP: net.ParseIP("192.168.178.25"),
		Log: logrus.NewEntry(logrus.New())}
	_, err := sut.Resolve(request)

	assert.NoError(t, err)
	assert.Len(t, request.ClientNames, 1)
	assert.Equal(t, "192.168.178.25", request.ClientNames[0])
}

func TestClientInfoWithoutIp(t *testing.T) {
	sut := NewClientNamesResolver(config.ClientLookupConfig{Upstream: config.Upstream{Net: "tcp", Host: "host"}})
	m := &resolverMock{}
	m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
	sut.Next(m)

	request := &Request{ClientIP: nil,
		Log: logrus.NewEntry(logrus.New())}
	_, err := sut.Resolve(request)

	assert.NoError(t, err)
	assert.Len(t, request.ClientNames, 0)
}

func TestClientInfoWithoutUpstream(t *testing.T) {
	sut := NewClientNamesResolver(config.ClientLookupConfig{})
	m := &resolverMock{}
	m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
	sut.Next(m)

	request := &Request{ClientIP: net.ParseIP("192.168.178.25"),
		Log: logrus.NewEntry(logrus.New())}
	_, err := sut.Resolve(request)

	assert.NoError(t, err)
	assert.Len(t, request.ClientNames, 1)
	assert.Equal(t, "192.168.178.25", request.ClientNames[0])
}

func Test_Configuration_ClientNamesResolver(t *testing.T) {
	sut := NewClientNamesResolver(config.ClientLookupConfig{
		Upstream:        config.Upstream{Net: "tcp", Host: "host"},
		SingleNameOrder: []uint{1, 2},
	})
	c := sut.Configuration()
	assert.Len(t, c, 3)
}

func Test_Configuration_ClientNamesResolver_Disabled(t *testing.T) {
	sut := NewClientNamesResolver(config.ClientLookupConfig{})
	c := sut.Configuration()
	assert.Equal(t, []string{"deactivated, use only IP address"}, c)
}
