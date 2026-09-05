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

// nativeHistogramBucketFactor controls the resolution of native histograms.
// The value of 1.05 is slightly higher accuracy than the default of 1.1.
const (
	nativeHistogramBucketFactor = 1.05

	labelClient       = "client"
	labelType         = "type"
	labelReason       = "reason"
	labelResponseCode = "response_code"
	labelResponseType = "response_type"

	// responseTypeErr is the synthetic response_type used when the chain returned no
	// response at all. It is not part of the model.ResponseType enum, so metrics using
	// the response_type label can carry it in addition to the enum values.
	responseTypeErr = "err"
)

// MetricsResolver resolver that records metrics about requests/response
type MetricsResolver struct {
	configurable[*config.Metrics]
	NextResolver
	typed

	totalQueries        *prometheus.CounterVec
	totalResponse       *prometheus.CounterVec
	totalClientResponse *prometheus.CounterVec
	totalErrors         prometheus.Counter
	durationHistogram   *prometheus.HistogramVec
}

// Resolve resolves the passed request
func (r *MetricsResolver) Resolve(ctx context.Context, request *model.Request) (*model.Response, error) {
	response, err := r.next.Resolve(ctx, request)

	if !r.cfg.Enable {
		return response, err
	}

	clientLabel := strings.Join(request.ClientNames, ",")

	// WithLabelValues is used instead of With(prometheus.Labels{...}) throughout: the map
	// literal costs an allocation per query on the hot path. The value order must match the
	// label order of the corresponding metric constructor below.
	r.totalQueries.WithLabelValues(clientLabel, dns.TypeToString[request.Req.Question[0].Qtype]).Inc()

	reqDuration := time.Since(request.RequestTS)
	responseType := responseTypeErr

	if response != nil {
		responseType = response.RType.String()
	}

	r.durationHistogram.WithLabelValues(responseType).Observe(reqDuration.Seconds())

	r.totalClientResponse.WithLabelValues(clientLabel, responseType).Inc()

	if err != nil {
		r.totalErrors.Inc()
	} else {
		// Prefer the low-cardinality ReasonLabel for the metric label; fall
		// back to Reason when it is not set. Blocked responses embed the
		// matched rule in Reason (e.g. a regex or domain), which is unbounded
		// for large deny lists, so they set ReasonLabel to the group names only.
		reasonLabel := response.ReasonLabel
		if reasonLabel == "" {
			reasonLabel = response.Reason
		}

		r.totalResponse.WithLabelValues(
			reasonLabel,
			dns.RcodeToString[response.Res.Rcode],
			response.RType.String(),
		).Inc()
	}

	return response, err
}

// NewMetricsResolver creates a new intance of the MetricsResolver type
func NewMetricsResolver(cfg config.Metrics) *MetricsResolver {
	m := MetricsResolver{
		configurable: withConfig(&cfg),
		typed:        withType("metrics"),

		durationHistogram:   durationHistogram(),
		totalQueries:        totalQueriesMetric(),
		totalResponse:       totalResponseMetric(),
		totalClientResponse: totalClientResponseMetric(),
		totalErrors:         totalErrorMetric(),
	}

	m.registerMetrics()

	return &m
}

func (r *MetricsResolver) registerMetrics() {
	metrics.RegisterMetric(r.durationHistogram)
	metrics.RegisterMetric(r.totalQueries)
	metrics.RegisterMetric(r.totalResponse)
	metrics.RegisterMetric(r.totalClientResponse)
	metrics.RegisterMetric(r.totalErrors)
}

func totalQueriesMetric() *prometheus.CounterVec {
	return prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "blocky_query_total",
			Help: "Number of total queries",
		}, []string{labelClient, labelType},
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
			Name:                        "blocky_request_duration_seconds",
			Help:                        "Request duration distribution",
			Buckets:                     []float64{0.005, 0.01, 0.02, 0.03, 0.05, 0.075, 0.1, 0.2, 0.5, 1.0, 2.0},
			NativeHistogramBucketFactor: nativeHistogramBucketFactor,
		},
		[]string{labelResponseType},
	)
}

func totalResponseMetric() *prometheus.CounterVec {
	return prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "blocky_response_total",
			Help: "Number of total responses",
		}, []string{labelReason, labelResponseCode, labelResponseType},
	)
}

func totalClientResponseMetric() *prometheus.CounterVec {
	return prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "blocky_client_response_total",
			Help: "Number of total responses per client and response type, " +
				"including failed requests as response_type=\"err\"",
		}, []string{labelClient, labelResponseType},
	)
}
