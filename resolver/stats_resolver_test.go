package resolver

import (
	"blocky/util"
	"testing"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func Test_Resolve_WithStats(t *testing.T) {
	sut := NewStatsResolver()
	m := &resolverMock{}

	resp, err := util.NewMsgWithAnswer("example.com. 300 IN A 123.122.121.120")
	assert.NoError(t, err)

	m.On("Resolve", mock.Anything).Return(&Response{Res: resp, Reason: "reason"}, nil)
	sut.Next(m)

	request := &Request{
		Req: util.NewMsgWithQuestion("example.com.", dns.TypeA),
		Log: logrus.NewEntry(logrus.New()),
	}

	_, err = sut.Resolve(request)
	assert.NoError(t, err)
	m.AssertExpectations(t)

	sut.(*StatsResolver).printStats()
}

func Test_Configuration_StatsResolverg(t *testing.T) {
	sut := NewStatsResolver()
	c := sut.Configuration()
	assert.True(t, len(c) > 1)
}
