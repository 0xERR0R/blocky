package resolver

import (
	"fmt"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/metrics"
	"github.com/0xERR0R/blocky/model"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
)

// MetricsResolver resolver that records metrics about requests/response
type MetricsResolver struct {
	NextResolver
	cfg               config.PrometheusConfig
	totalQueries      *prometheus.CounterVec
	totalResponse     *prometheus.CounterVec
	totalErrors       prometheus.Counter
	durationHistogram *prometheus.HistogramVec
}

// Resolve resolves the passed request
func (m *MetricsResolver) Resolve(request *model.Request) (*model.Response, error) {
	response, err := m.next.Resolve(request)

	if m.cfg.Enable {
		m.totalQueries.With(prometheus.Labels{
			"client": strings.Join(request.ClientNames, ","),
			"type":   dns.TypeToString[request.Req.Question[0].Qtype]}).Inc()

		reqDurationMs := float64(time.Since(request.RequestTS).Milliseconds())
		responseType := "err"

		if response != nil {
			responseType = response.RType.String()
		}

		m.durationHistogram.WithLabelValues(responseType).Observe(reqDurationMs)

		if err != nil {
			m.totalErrors.Inc()
		} else {
			m.totalResponse.With(prometheus.Labels{
				"reason":        response.Reason,
				"response_code": dns.RcodeToString[response.Res.Rcode],
				"response_type": response.RType.String()}).Inc()
		}
	}

	return response, err
}

// Configuration gets the config of this resolver in a string slice
func (m *MetricsResolver) Configuration() (result []string) {
	result = append(result, "metrics:")
	result = append(result, fmt.Sprintf("  Enable = %t", m.cfg.Enable))
	result = append(result, fmt.Sprintf("  Path   = %s", m.cfg.Path))

	return
}

// NewMetricsResolver creates a new intance of the MetricsResolver type
func NewMetricsResolver(cfg config.PrometheusConfig) ChainedResolver {
	durationHistogram := durationHistogram()
	totalQueries := totalQueriesMetric()
	totalResponse := totalResponseMetric()
	totalErrors := totalErrorMetric()

	metrics.RegisterMetric(durationHistogram)
	metrics.RegisterMetric(totalQueries)
	metrics.RegisterMetric(totalResponse)
	metrics.RegisterMetric(totalErrors)

	return &MetricsResolver{
		cfg:               cfg,
		durationHistogram: durationHistogram,
		totalQueries:      totalQueries,
		totalResponse:     totalResponse,
		totalErrors:       totalErrors,
	}
}

func totalQueriesMetric() *prometheus.CounterVec {
	return prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "blocky_query_total",
			Help: "Number of total queries",
		}, []string{"client", "type"},
	)
}

func totalErrorMetric() prometheus.Counter {
	return prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "blocky_error_total",
			Help: "Number of total errors",
		},
	)
}

func durationHistogram() *prometheus.HistogramVec {
	return prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "blocky_request_duration_ms",
			Help:    "Request duration distribution",
			Buckets: []float64{5, 10, 20, 30, 50, 75, 100, 200, 500, 1000, 2000},
		},
		[]string{"response_type"},
	)
}

func totalResponseMetric() *prometheus.CounterVec {
	return prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "blocky_response_total",
			Help: "Number of total responses",
		}, []string{"reason", "response_code", "response_type"},
	)
}
