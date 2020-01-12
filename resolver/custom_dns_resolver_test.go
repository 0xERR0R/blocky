package resolver

import (
	"blocky/config"
	"blocky/util"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func Test_Resolve_Custom_Name_Ip4_A(t *testing.T) {
	sut := NewCustomDNSResolver(config.CustomDNSConfig{
		Mapping: map[string]net.IP{"custom.domain": net.ParseIP("192.168.143.123")}})
	m := &resolverMock{}
	sut.Next(m)

	request := &Request{
		Req: util.NewMsgWithQuestion("custom.domain.", dns.TypeA),
		Log: logrus.NewEntry(logrus.New()),
	}

	resp, err := sut.Resolve(request)
	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Res.Rcode)
	assert.Equal(t, "custom.domain.	3600	IN	A	192.168.143.123", resp.Res.Answer[0].String())
	m.AssertNotCalled(t, "Resolve", mock.Anything)
}

func Test_Resolve_Custom_Name_Ip4_AAAA(t *testing.T) {
	sut := NewCustomDNSResolver(config.CustomDNSConfig{
		Mapping: map[string]net.IP{"custom.domain": net.ParseIP("192.168.143.123")}})
	m := &resolverMock{}
	sut.Next(m)

	request := &Request{
		Req: util.NewMsgWithQuestion("custom.domain.", dns.TypeAAAA),
		Log: logrus.NewEntry(logrus.New()),
	}

	resp, err := sut.Resolve(request)
	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeNameError, resp.Res.Rcode)
	m.AssertNotCalled(t, "Resolve", mock.Anything)
}

func Test_Resolve_Custom_Name_Ip6_AAAA(t *testing.T) {
	sut := NewCustomDNSResolver(config.CustomDNSConfig{
		Mapping: map[string]net.IP{"custom.domain": net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334")}})
	m := &resolverMock{}
	sut.Next(m)

	request := &Request{
		Req: util.NewMsgWithQuestion("custom.domain.", dns.TypeAAAA),
		Log: logrus.NewEntry(logrus.New()),
	}
	resp, err := sut.Resolve(request)
	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Res.Rcode)
	assert.Equal(t, "custom.domain.	3600	IN	AAAA	2001:db8:85a3::8a2e:370:7334", resp.Res.Answer[0].String())
	m.AssertNotCalled(t, "Resolve", mock.Anything)
}

func Test_Resolve_Custom_Name_Subdomain(t *testing.T) {
	sut := NewCustomDNSResolver(config.CustomDNSConfig{
		Mapping: map[string]net.IP{"custom.domain": net.ParseIP("192.168.143.123")}})
	m := &resolverMock{}
	m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
	sut.Next(m)

	request := &Request{
		Req: util.NewMsgWithQuestion("ABC.CUSTOM.DOMAIN.", dns.TypeA),
		Log: logrus.NewEntry(logrus.New()),
	}

	resp, err := sut.Resolve(request)
	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Res.Rcode)
	assert.Equal(t, "ABC.CUSTOM.DOMAIN.	3600	IN	A	192.168.143.123", resp.Res.Answer[0].String())
	m.AssertNotCalled(t, "Resolve", mock.Anything)
}

func Test_Resolve_Delegate_Next(t *testing.T) {
	sut := NewCustomDNSResolver(config.CustomDNSConfig{
		Mapping: map[string]net.IP{"custom.domain": net.ParseIP("192.168.143.123")}})
	m := &resolverMock{}
	m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
	sut.Next(m)

	request := &Request{
		Req: util.NewMsgWithQuestion("example.com.", dns.TypeA),
		Log: logrus.NewEntry(logrus.New()),
	}

	_, _ = sut.Resolve(request)

	m.AssertExpectations(t)
}
