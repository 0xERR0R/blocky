package resolver

import (
	"blocky/config"
	"blocky/util"
	"crypto/tls"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func Test_Resolve_DNSUpstream(t *testing.T) {
	upstream := TestUDPUpstream(func(request *dns.Msg) *dns.Msg {
		response, err := util.NewMsgWithAnswer("example.com 123 IN A 123.124.122.122")

		assert.NoError(t, err)
		return response
	})

	sut := NewUpstreamResolver(upstream)

	request := &Request{
		Req: util.NewMsgWithQuestion("example.com.", dns.TypeA),
		Log: logrus.NewEntry(logrus.New()),
	}

	resp, err := sut.Resolve(request)
	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Res.Rcode)
	assert.Equal(t, "example.com.	123	IN	A	123.124.122.122", resp.Res.Answer[0].String())
}

func Test_Resolve_DOHUpstream(t *testing.T) {
	upstream := TestDOHUpstream(func(request *dns.Msg) *dns.Msg {
		response, err := util.NewMsgWithAnswer("example.com 123 IN A 123.124.122.122")

		assert.NoError(t, err)
		return response
	})
	sut := NewUpstreamResolver(upstream).(*UpstreamResolver)

	// use unsecure certificates for test doh upstream
	// nolint:gosec
	sut.upstreamClient.(*httpUpstreamClient).client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	request := &Request{
		Req: util.NewMsgWithQuestion("example.com.", dns.TypeA),
		Log: logrus.NewEntry(logrus.New()),
	}

	resp, err := sut.Resolve(request)
	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Res.Rcode)
	assert.Equal(t, "example.com.	123	IN	A	123.124.122.122", resp.Res.Answer[0].String())
}

func Test_Resolve_DOHUpstream_WrongResponseCode(t *testing.T) {
	upstream := TestDOHUpstream(func(request *dns.Msg) *dns.Msg {
		response, err := util.NewMsgWithAnswer("example.com 123 IN A 123.124.122.122")

		assert.NoError(t, err)
		return response
	}, func(w http.ResponseWriter) {
		w.WriteHeader(500)
	})
	sut := NewUpstreamResolver(upstream).(*UpstreamResolver)

	// use unsecure certificates for test doh upstream
	// nolint:gosec
	sut.upstreamClient.(*httpUpstreamClient).client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	request := &Request{
		Req: util.NewMsgWithQuestion("example.com.", dns.TypeA),
		Log: logrus.NewEntry(logrus.New()),
	}

	_, err := sut.Resolve(request)
	assert.Error(t, err)
	assert.Equal(t, "http return code should be 200, but received 500", err.Error())
}

func Test_Resolve_DOHUpstream_WrongResponseContentType(t *testing.T) {
	upstream := TestDOHUpstream(func(request *dns.Msg) *dns.Msg {
		response, err := util.NewMsgWithAnswer("example.com 123 IN A 123.124.122.122")

		assert.NoError(t, err)
		return response
	}, func(w http.ResponseWriter) {
		w.Header().Set("content-type", "text")
	})
	sut := NewUpstreamResolver(upstream).(*UpstreamResolver)

	// use unsecure certificates for test doh upstream
	// nolint:gosec
	sut.upstreamClient.(*httpUpstreamClient).client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	request := &Request{
		Req: util.NewMsgWithQuestion("example.com.", dns.TypeA),
		Log: logrus.NewEntry(logrus.New()),
	}

	_, err := sut.Resolve(request)
	assert.Error(t, err)
	assert.Equal(t, "http return content type should be 'application/dns-message', but was 'text'", err.Error())
}

func Test_Resolve_DOHUpstream_WrongResponseContent(t *testing.T) {
	upstream := TestDOHUpstream(func(request *dns.Msg) *dns.Msg {
		response, err := util.NewMsgWithAnswer("example.com 123 IN A 123.124.122.122")

		assert.NoError(t, err)
		return response
	}, func(w http.ResponseWriter) {
		_, _ = w.Write([]byte("wrongcontent"))
	})
	sut := NewUpstreamResolver(upstream).(*UpstreamResolver)

	// use unsecure certificates for test doh upstream
	// nolint:gosec
	sut.upstreamClient.(*httpUpstreamClient).client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	request := &Request{
		Req: util.NewMsgWithQuestion("example.com.", dns.TypeA),
		Log: logrus.NewEntry(logrus.New()),
	}

	_, err := sut.Resolve(request)
	assert.Error(t, err)
	assert.Equal(t, "can't unpack message", err.Error())
}

func Test_Resolve_DOHUpstream_NoResponse(t *testing.T) {
	sut := NewUpstreamResolver(config.Upstream{Net: "https", Host: "wronghost.example.com"})

	request := &Request{
		Req: util.NewMsgWithQuestion("example.com.", dns.TypeA),
		Log: logrus.NewEntry(logrus.New()),
	}

	_, err := sut.Resolve(request)
	assert.Error(t, err)
}

func Test_Resolve_DOHUpstream_WrongInput(t *testing.T) {
	sut := NewUpstreamResolver(config.Upstream{Net: "https", Host: "wronghost.example.com"})

	wrongResp := new(dns.Msg)
	wrongResp.Rcode = -5

	request := &Request{
		Req: wrongResp,
		Log: logrus.NewEntry(logrus.New()),
	}

	_, err := sut.Resolve(request)
	assert.Error(t, err)
}

func Test_Resolve_UpstreamTimeout(t *testing.T) {
	counter := 0
	attemptsWithTimeout := 2

	upstream := TestUDPUpstream(func(request *dns.Msg) (response *dns.Msg) {
		counter++
		// timeout on first x attempts
		if counter <= attemptsWithTimeout {
			time.Sleep(110 * time.Millisecond)
		}
		response, err := util.NewMsgWithAnswer("example.com 123 IN A 123.124.122.122")
		assert.NoError(t, err)

		return response
	})

	sut := NewUpstreamResolver(upstream).(*UpstreamResolver)
	sut.upstreamClient.(*dnsUpstreamClient).client.Timeout = 100 * time.Millisecond

	request := &Request{
		Req: util.NewMsgWithQuestion("example.com.", dns.TypeA),
		Log: logrus.NewEntry(logrus.New()),
	}

	// first request -> after 2 timeouts success
	response, err := sut.Resolve(request)
	assert.NoError(t, err)

	if response != nil {
		assert.Equal(t, dns.RcodeSuccess, response.Res.Rcode)
		assert.Equal(t, "example.com.\t123\tIN\tA\t123.124.122.122", response.Res.Answer[0].String())
	}

	attemptsWithTimeout = 3
	counter = 0

	// second request
	// all 3 attempts with timeout
	response, err = sut.Resolve(request)
	assert.Error(t, err)
	assert.True(t, strings.HasSuffix(err.Error(), "i/o timeout"))
	assert.Nil(t, response)
}

func Test_Configuration_UpstreamResolver(t *testing.T) {
	sut := NewUpstreamResolver(config.Upstream{})

	c := sut.Configuration()

	assert.Nil(t, c)
}
