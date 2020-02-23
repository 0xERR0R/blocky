package resolver

import (
	"blocky/config"
	"blocky/util"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func Test_Resolve_Best_Result(t *testing.T) {
	fast := TestUDPUpstream(func(request *dns.Msg) *dns.Msg {
		response, err := util.NewMsgWithAnswer("example.com 123 IN A 123.124.122.122")

		assert.NoError(t, err)
		return response
	})

	slow := TestUDPUpstream(func(request *dns.Msg) *dns.Msg {
		response, err := util.NewMsgWithAnswer("example.com 123 IN A 123.124.122.123")
		time.Sleep(50 * time.Millisecond)

		assert.NoError(t, err)
		return response
	})

	sut := NewParallelBestResolver(config.UpstreamConfig{ExternalResolvers: []config.Upstream{fast, slow}})

	resp, err := sut.Resolve(&Request{
		Req: util.NewMsgWithQuestion("example.com.", dns.TypeA),
		Log: logrus.NewEntry(logrus.New()),
	})

	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Res.Rcode)
	assert.Equal(t, "example.com.	123	IN	A	123.124.122.122", resp.Res.Answer[0].String())
}

func Test_Resolve_BestWithOne(t *testing.T) {
	upstream := TestUDPUpstream(func(request *dns.Msg) *dns.Msg {
		response, err := util.NewMsgWithAnswer("example.com 123 IN A 123.124.122.122")

		assert.NoError(t, err)
		return response
	})

	sut := NewParallelBestResolver(config.UpstreamConfig{ExternalResolvers: []config.Upstream{upstream}})

	resp, err := sut.Resolve(&Request{
		Req: util.NewMsgWithQuestion("example.com.", dns.TypeA),
		Log: logrus.NewEntry(logrus.New()),
	})

	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Res.Rcode)
	assert.Equal(t, "example.com.	123	IN	A	123.124.122.122", resp.Res.Answer[0].String())
}

func Test_Resolve_One_Error(t *testing.T) {
	withError := config.Upstream{Host: "wrong"}

	slow := TestUDPUpstream(func(request *dns.Msg) *dns.Msg {
		response, err := util.NewMsgWithAnswer("example.com 123 IN A 123.124.122.123")
		time.Sleep(50 * time.Millisecond)

		assert.NoError(t, err)
		return response
	})

	sut := NewParallelBestResolver(config.UpstreamConfig{ExternalResolvers: []config.Upstream{withError, slow}})

	resp, err := sut.Resolve(&Request{
		Req: util.NewMsgWithQuestion("example.com.", dns.TypeA),
		Log: logrus.NewEntry(logrus.New()),
	})

	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Res.Rcode)
	assert.Equal(t, "example.com.	123	IN	A	123.124.122.123", resp.Res.Answer[0].String())
}

func Test_Resolve_All_Error(t *testing.T) {
	withError1 := config.Upstream{Host: "wrong"}
	withError2 := config.Upstream{Host: "wrong"}

	sut := NewParallelBestResolver(config.UpstreamConfig{ExternalResolvers: []config.Upstream{withError1, withError2}})

	resp, err := sut.Resolve(&Request{
		Req: util.NewMsgWithQuestion("example.com.", dns.TypeA),
		Log: logrus.NewEntry(logrus.New()),
	})

	assert.Error(t, err)
	assert.Nil(t, resp)
}

func Test_Configuration_ParallelResolver(t *testing.T) {
	sut := NewParallelBestResolver(config.UpstreamConfig{
		ExternalResolvers: []config.Upstream{
			{Host: "host1"},
			{Host: "host2"},
		}})

	c := sut.Configuration()

	assert.Len(t, c, 3)
}

func Test_PickRandom(t *testing.T) {
	sut := NewParallelBestResolver(config.UpstreamConfig{
		ExternalResolvers: []config.Upstream{
			{Host: "host1"},
			{Host: "host2"},
			{Host: "host3"}}})

	r1, r2 := sut.(*ParallelBestResolver).pickRandom()

	assert.NotEqual(t, r1, r2)
}
