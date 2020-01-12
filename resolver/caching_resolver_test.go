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

func Test_Resolve_A_WithCachingAndMinTtl(t *testing.T) {
	sut := NewCachingResolver()
	m := &resolverMock{}
	mockResp, err := util.NewMsgWithAnswer("example.com. 300 IN A 123.122.121.120")

	if err != nil {
		t.Error(err)
	}

	m.On("Resolve", mock.Anything).Return(&Response{Res: mockResp}, nil)
	sut.Next(m)

	request := &Request{
		Req: util.NewMsgWithQuestion("example.com.", dns.TypeA),
		Log: logrus.NewEntry(logrus.New()),
	}

	// first request
	resp, err := sut.Resolve(request)
	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Res.Rcode)
	assert.Equal(t, "example.com.	300	IN	A	123.122.121.120", resp.Res.Answer[0].String())
	assert.Equal(t, 1, len(m.Calls))

	time.Sleep(500 * time.Millisecond)

	// second request
	resp, err = sut.Resolve(request)
	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Res.Rcode)

	// ttl is smaler
	assert.Equal(t, "example.com.	299	IN	A	123.122.121.120", resp.Res.Answer[0].String())

	// still one call to resolver
	assert.Equal(t, 1, len(m.Calls))

	m.AssertExpectations(t)
}

func Test_Resolve_AAAA_WithCachingAndMinTtl(t *testing.T) {
	sut := NewCachingResolver()
	m := &resolverMock{}

	mockResp, err := util.NewMsgWithAnswer("example.com. 123 IN AAAA 2001:0db8:85a3:08d3:1319:8a2e:0370:7344")

	if err != nil {
		t.Error(err)
	}

	m.On("Resolve", mock.Anything).Return(&Response{Res: mockResp}, nil)
	sut.Next(m)

	request := &Request{
		Req: util.NewMsgWithQuestion("example.com.", dns.TypeAAAA),
		Log: logrus.NewEntry(logrus.New()),
	}

	// first request
	resp, err := sut.Resolve(request)
	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Res.Rcode)
	assert.Equal(t, "example.com.	250	IN	AAAA	2001:db8:85a3:8d3:1319:8a2e:370:7344", resp.Res.Answer[0].String())
	assert.Equal(t, 1, len(m.Calls))

	time.Sleep(500 * time.Millisecond)

	// second request
	resp, err = sut.Resolve(request)
	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Res.Rcode)

	// ttl is smaler
	assert.Equal(t, "example.com.	249	IN	AAAA	2001:db8:85a3:8d3:1319:8a2e:370:7344", resp.Res.Answer[0].String())

	// still one call to resolver
	assert.Equal(t, 1, len(m.Calls))

	m.AssertExpectations(t)
}

func Test_Resolve_MX(t *testing.T) {
	sut := NewCachingResolver()
	m := &resolverMock{}
	mockResp, err := util.NewMsgWithAnswer("google.de.\t180\tIN\tMX\t20\talt1.aspmx.l.google.com.")

	if err != nil {
		t.Error(err)
	}

	m.On("Resolve", mock.Anything).Return(&Response{Res: mockResp}, nil)
	sut.Next(m)

	request := &Request{
		Req: util.NewMsgWithQuestion("google.de.", dns.TypeMX),
		Log: logrus.NewEntry(logrus.New()),
	}

	resp, err := sut.Resolve(request)
	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Res.Rcode)
	assert.Equal(t, "google.de.\t180\tIN\tMX\t20 alt1.aspmx.l.google.com.", resp.Res.Answer[0].String())
	assert.Equal(t, 1, len(m.Calls))
}
