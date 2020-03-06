package resolver

import (
	"blocky/config"
	"blocky/util"
	"errors"
	"testing"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func Test_Resolve_Record_Stats(t *testing.T) {
	cfg := config.PrometheusConfig{Enable: true}
	resolv := NewMetricsResolver(cfg).(*MetricsResolver)

	nextOne := resolverMock{}
	nextOne.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
	resolv.Next(&nextOne)

	req := Request{
		Req:         util.NewMsgWithQuestion("example.com.", dns.TypeA),
		Log:         logrus.NewEntry(logrus.New()),
		ClientNames: []string{"client"},
	}

	resp, err := resolv.Resolve(&req)
	assert.NoError(t, err)

	cnt, err := resolv.totalQueries.GetMetricWith(prometheus.Labels{"client": "client", "type": "A"})
	assert.NoError(t, err)
	assert.Equal(t, float64(1), testutil.ToFloat64(cnt))

	assert.Equal(t, dns.RcodeSuccess, resp.Res.Rcode)
	nextOne.AssertExpectations(t)
}

func Test_Resolve_Record_Error(t *testing.T) {
	cfg := config.PrometheusConfig{Enable: true}
	resolv := NewMetricsResolver(cfg).(*MetricsResolver)

	nextOne := resolverMock{}
	nextOne.On("Resolve", mock.Anything).Return(nil, errors.New("error"))
	resolv.Next(&nextOne)

	req := Request{
		Req:         util.NewMsgWithQuestion("example.com.", dns.TypeA),
		Log:         logrus.NewEntry(logrus.New()),
		ClientNames: []string{"client"},
	}

	_, err := resolv.Resolve(&req)
	assert.Error(t, err)

	assert.Equal(t, float64(1), testutil.ToFloat64(resolv.totalErrors))

	nextOne.AssertExpectations(t)
}

func Test_Configuration_MetricsResolver(t *testing.T) {
	sut := NewMetricsResolver(config.PrometheusConfig{Enable: true})
	c := sut.Configuration()
	assert.Len(t, c, 3)
}
