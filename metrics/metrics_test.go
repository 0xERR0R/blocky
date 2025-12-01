package metrics_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/evt"
	"github.com/0xERR0R/blocky/lists"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/metrics"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/resolver"

	"github.com/go-chi/chi/v5"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

func init() {
	log.Silence() // Silence log output during tests
}

func AssertRegistryComplete(t *testing.T, reg *prometheus.Registry) {
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}

	if len(mfs) == 0 {
		t.Fatal("no metrics were gathered; registry appears to be empty")
	}

	found := make(map[string]struct{})
	for _, mf := range mfs {
		name := mf.GetName()
		if strings.HasPrefix(name, "go_") ||
			strings.HasPrefix(name, "process_") ||
			strings.HasPrefix(name, "promhttp_") {
			continue
		}
		found[name] = struct{}{}
	}

	expected := []string{
		// these require a BlockingCacheGroupChanged event
		"blocky_denylist_cache_entries",
		"blocky_allowlist_cache_entries",
		// these require a request
		"blocky_query_total",
		"blocky_request_duration_seconds",
		"blocky_response_total",
		// these should be default
		"blocky_error_total",
		"blocky_blocking_enabled",
		"blocky_cache_entries",
		"blocky_cache_hits_total",
		"blocky_cache_misses_total",
		"blocky_last_list_group_refresh_timestamp_seconds",
		"blocky_prefetches_total",
		"blocky_prefetch_hits_total",
		"blocky_prefetch_domain_name_cache_entries",
		"blocky_failed_downloads_total",
	}

	if len(found) != len(expected) {
		t.Errorf("Found %d / %d expected metrics", len(found), len(expected))
	}

	// helperto check if a string is in a slice
	contains := func(slice []string, item string) bool {
		for _, s := range slice {
			if s == item {
				return true
			}
		}

		return false
	}

	for name := range found {
		if !contains(expected, name) {
			t.Errorf("found additional metric %q in registry", name)
		}
	}

	for _, name := range expected {
		if _, ok := found[name]; !ok {
			t.Errorf("expected metric %q not found in registry", name)
		}
	}
}

type MockResolver struct{}

func (m *MockResolver) Resolve(ctx context.Context, request *model.Request) (*model.Response, error) {
	resp := &model.Response{
		Res:    &dns.Msg{},
		Reason: "mocking",
		RType:  0,
	}

	return resp, nil
}

func (m *MockResolver) IsEnabled() bool {
	return true
}

func (m *MockResolver) LogConfig(*logrus.Entry) {
	// no-op for testing
}

func (m *MockResolver) String() string {
	return "mockResolver"
}

func (m *MockResolver) Type() string {
	return "MockResolver"
}

func TestAllExpectedMetricsAreRegistered(t *testing.T) {
	// New Server
	metrics.RegisterEventListeners()

	config := config.Metrics{Enable: true, Path: "/metrics"}

	// createQueryResolver
	metricsResolver := resolver.NewMetricsResolver(config)
	metricsResolver.Next(&MockResolver{})

	// prepare request
	dnsMsg := new(dns.Msg)
	dnsMsg.SetQuestion("example.com.", dns.TypeA)

	req := model.Request{
		ClientIP:        net.ParseIP("192.168.0.1"),
		RequestClientID: "test-client",
		Protocol:        model.RequestProtocolUDP,
		ClientNames:     []string{"test-client"},
		Req:             dnsMsg,
		RequestTS:       time.Now().Add(-42 * time.Millisecond),
	}

	ctx := context.Background()
	// now use the counters
	_, err := metricsResolver.Resolve(ctx, &req)
	if err != nil {
		t.Fatal("failed to call metrics resolver")
	}
	evt.Bus().Publish(evt.BlockingCacheGroupChanged, lists.ListCacheTypeDenylist, "group", 0)
	evt.Bus().Publish(evt.BlockingCacheGroupChanged, lists.ListCacheTypeAllowlist, "group", 0)

	// createHTTPRouter
	metrics.Start(chi.NewMux(), config)

	AssertRegistryComplete(t, metrics.Reg)
}
