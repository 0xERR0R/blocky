package resolver

import (
	"blocky/util"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func Test_Resolve_Upstream(t *testing.T) {
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

func TestUpstreamTimeout(t *testing.T) {
	counter := 0
	attemptsWithTimeout := 2

	upstream := TestUDPUpstream(func(request *dns.Msg) (response *dns.Msg) {
		counter++
		// timeout on first x attempts
		if counter <= attemptsWithTimeout {
			fmt.Print("timeout")
			time.Sleep(110 * time.Millisecond)
		}
		response, err := util.NewMsgWithAnswer("example.com 123 IN A 123.124.122.122")
		assert.NoError(t, err)

		return response
	})

	sut := NewUpstreamResolver(upstream).(*UpstreamResolver)
	sut.client.ReadTimeout = 100 * time.Millisecond

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
