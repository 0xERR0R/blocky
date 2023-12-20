package resolver

import (
	"context"
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
	configurable[*config.Metrics]
	NextResolver
	typed

	totalQueries      *prometheus.CounterVec
	totalResponse     *prometheus.CounterVec
	totalErrors       prometheus.Counter
	durationHistogram *prometheus.HistogramVec
}

// Resolve resolves the passed request
func (r *MetricsResolver) Resolve(ctx context.Context, request *model.Request) (*model.Response, error) {
	response, err := r.next.Resolve(ctx, request)

	if r.cfg.Enable {
		r.totalQueries.With(prometheus.Labels{
			"client": strings.Join(request.ClientNames, ","),
			"type":   dns.TypeToString[request.Req.Question[0].Qtype],
		}).Inc()

		reqDurationMs := float64(time.Since(request.RequestTS).Milliseconds())
		responseType := "err"

		if response != nil {
			responseType = response.RType.String()
		}

		r.durationHistogram.WithLabelValues(responseType).Observe(reqDurationMs)

		if err != nil {
			r.totalErrors.Inc()
		} else {
			r.totalResponse.With(prometheus.Labels{
				"reason":        response.Reason,
				"response_code": dns.RcodeToString[response.Res.Rcode],
				"response_type": response.RType.String(),
			}).Inc()
		}
	}

	return response, err
}

// NewMetricsResolver creates a new intance of the MetricsResolver type
func NewMetricsResolver(cfg config.Metrics) *MetricsResolver {
	m := MetricsResolver{
		configurable: withConfig(&cfg),
		typed:        withType("metrics"),

		durationHistogram: durationHistogram(),
		totalQueries:      totalQueriesMetric(),
		totalResponse:     totalResponseMetric(),
		totalErrors:       totalErrorMetric(),
	}

	m.registerMetrics()

	return &m
}

func (r *MetricsResolver) registerMetrics() {
	metrics.RegisterMetric(r.durationHistogram)
	metrics.RegisterMetric(r.totalQueries)
	metrics.RegisterMetric(r.totalResponse)
	metrics.RegisterMetric(r.totalErrors)
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
