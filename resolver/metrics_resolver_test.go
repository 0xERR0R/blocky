package resolver

import (
	"blocky/config"
	"blocky/util"
	"testing"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func Test_Call_Record_Stats(t *testing.T) {
	cfg := config.PrometheusConfig{Enable: true}
	resolv := NewMetricsResolver(cfg)
	mockMetrics := metricsMock{}
	mockMetrics.On("RecordStats", mock.Anything, mock.Anything).Once()
	resolv.metrics = &mockMetrics

	nextOne := resolverMock{}
	nextOne.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
	resolv.Next(&nextOne)

	req := Request{
		Req: util.NewMsgWithQuestion("example.com.", dns.TypeA),
		Log: logrus.NewEntry(logrus.New()),
	}
	resp, err := resolv.Resolve(&req)

	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Res.Rcode)
	nextOne.AssertExpectations(t)
	mockMetrics.AssertExpectations(t)
}
