# Prometheus Metrics Instrumentation Best Practices - Research Report

**Date**: March 13, 2026  
**Research Focus**: Industry best practices for metrics instrumentation in Go applications with Prometheus, specifically for chain-of-responsibility patterns

---

## Executive Summary

This report synthesizes industry best practices for Prometheus metrics instrumentation in Go applications, with specific focus on how they apply to chain-of-responsibility patterns like Blocky's DNS resolver chain.

**Key Findings**:
- **Dependency Injection**: Interface-based injection is the recommended pattern over global state
- **Registry Management**: Custom registries are preferred over global default registry
- **Testing**: Mock-based testing using interfaces is recommended over direct metric value inspection
- **Cardinality Management**: Label cardinality is the #1 performance issue in Prometheus
- **Chain-of-Responsibility**: Middleware pattern metrics align naturally with resolver chains

---

## 1. Recommended Patterns

### 1.1 Dependency Injection Pattern

**Pattern**: Inject `prometheus.Registerer` interface instead of using global registry

**Example**:
```go
type Metrics struct {
    queries *prometheus.CounterVec
    latency *prometheus.HistogramVec
}

func NewMetrics(reg prometheus.Registerer) *Metrics {
    m := &Metrics{
        queries: prometheus.NewCounterVec(
            prometheus.CounterOpts{
                Name: "resolver_queries_total",
                Help: "Total queries processed",
            },
            []string{"resolver", "type"},
        ),
        latency: prometheus.NewHistogramVec(
            prometheus.HistogramOpts{
                Name: "resolver_duration_seconds",
                Help: "Query processing duration",
            },
            []string{"resolver"},
        ),
    }
    
    reg.MustRegister(m.queries, m.latency)
    return m
}
```

**Pros**:
- Testable: can inject mock registry
- Flexible: different resolvers can use different registries
- SOLID: Dependency Inversion Principle satisfied
- No global state: easier to reason about and refactor

**Cons**:
- More boilerplate code
- Requires passing registry through constructor chain

**Fit for Blocky**: **EXCELLENT** - Aligns perfectly with resolver chain where each resolver is instantiated with its own config

---

### 1.2 Custom Registry Pattern

**Pattern**: Create application-specific registry instead of using global `prometheus.DefaultRegisterer`

**Example**:
```go
// In metrics package
package metrics

var Reg = prometheus.NewRegistry()

func RegisterMetric(c prometheus.Collector) {
    _ = Reg.Register(c)
}

func Start(router *chi.Mux, cfg config.Metrics) {
    if cfg.Enable {
        Reg.Register(collectors.NewGoCollector())
        Reg.Register(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
        router.Handle(cfg.Path, promhttp.HandlerFor(Reg, promhttp.HandlerOpts{}))
    }
}
```

**Evidence** ([Prometheus Go Client Docs](https://prometheus.io/docs/guides/go-application/)):
> Create a non-global registry. This avoids collisions with default metrics and makes testing easier.

**Pros**:
- Isolation: separate metrics namespace
- Testing: clean registry for each test
- Control: can choose which collectors to register

**Cons**:
- Manual management: need to track what's registered
- No auto-discovery: can't use promauto

**Fit for Blocky**: **GOOD** - Already implemented this pattern! Current `metrics.Reg` follows this best practice

---

### 1.3 Metrics Structure Pattern

**Pattern**: Group metrics in struct and provide methods for recording

**Example**:
```go
type ResolverMetrics struct {
    queries      *prometheus.CounterVec
    responses    *prometheus.CounterVec
    errors       prometheus.Counter
    duration     *prometheus.HistogramVec
}

func (m *ResolverMetrics) RecordQuery(client, qtype string) {
    m.queries.WithLabelValues(client, qtype).Inc()
}

func (m *ResolverMetrics) RecordResponse(rtype, code string, duration time.Duration) {
    m.responses.WithLabelValues(rtype, code).Inc()
    m.duration.WithLabelValues(rtype).Observe(duration.Seconds())
}

func (m *ResolverMetrics) RecordError() {
    m.errors.Inc()
}
```

**Pros**:
- Encapsulation: metrics logic in one place
- Readability: semantic method names
- SOLID: Single Responsibility - only handles metric recording

**Cons**:
- More code
- Indirection: one more layer

**Fit for Blocky**: **EXCELLENT** - Currently has metrics as fields but no recording methods. Would improve testability

---

### 1.4 Middleware/Chain Pattern for Metrics

**Pattern**: Metrics as middleware in chain-of-responsibility

**Example**:
```go
type MetricsMiddleware struct {
    metrics *ResolverMetrics
    next    Resolver
}

func (m *MetricsMiddleware) Resolve(ctx context.Context, req *Request) (*Response, error) {
    start := time.Now()
    resp, err := m.next.Resolve(ctx, req)
    duration := time.Since(start)
    
    // Record metrics
    m.metrics.RecordQuery(req.Client, req.Type)
    if err != nil {
        m.metrics.RecordError()
    } else {
        m.metrics.RecordResponse(resp.Type, resp.Code, duration)
    }
    
    return resp, err
}
```

**Evidence** ([HTTP Middleware Pattern](https://oneuptime.com/blog/post/2026-01-30-go-middleware-chains-http/view)):
> Middleware sits between incoming request and your actual handler. It can inspect requests, modify responses, or pass control to next handler in chain.

**Pros**:
- Natural fit for chain-of-responsibility
- Consistent pattern across all resolvers
- Easy to enable/disable
- Separates concerns: resolver logic vs metrics

**Cons**:
- Adds to chain length (performance consideration)
- Need to ensure metrics don't break chain

**Fit for Blocky**: **PERFECT** - This is exactly how `MetricsResolver` currently works in Blocky!

---

### 1.5 Histogram with Native Buckets

**Pattern**: Use native histograms for better resolution

**Example**:
```go
durationHistogram := prometheus.NewHistogramVec(
    prometheus.HistogramOpts{
        Name:                        "request_duration_seconds",
        Help:                        "Request duration distribution",
        Buckets:                     []float64{0.005, 0.01, 0.02, 0.03, 0.05, 0.075, 0.1, 0.2, 0.5, 1.0, 2.0},
        NativeHistogramBucketFactor: 1.05, // Better resolution than default 1.1
    },
    []string{"response_type"},
)
```

**Evidence** ([Prometheus Native Histograms](https://prometheus.io/docs/specs/native_histograms/)):
> Native histograms provide a more efficient way to store distributions with configurable bucket factors.

**Pros**:
- Higher resolution than standard histograms
- Better for percentile calculations
- More efficient storage

**Cons**:
- Requires Prometheus 2.40+ (may not be available everywhere)
- Slightly more complex setup

**Fit for Blocky**: **GOOD** - Already using this pattern! Current implementation uses `NativeHistogramBucketFactor: 1.05`

---

## 2. Anti-Patterns to Avoid

### 2.1 High Cardinality Labels

**Anti-Pattern**: Using labels with unbounded or very high cardinality

**Bad Example**:
```go
// BAD: User ID creates millions of series
queries.WithLabelValues(user_id).Inc()

// BAD: Request ID is unique per request
queries.WithLabelValues(request_id).Inc()

// BAD: Domain names can be infinite
queries.WithLabelValues(domain).Inc()
```

**Evidence** ([High Cardinality Article](https://oneuptime.com/blog/post/2026-01-25-prometheus-metric-cardinality/view)):
> High cardinality impacts memory usage, query performance, storage costs, and scrape time. Each unique combination of metric name and label values creates a separate time series.

**Current Blocky Risk**:
- `blocky_query_total{client=..., type=...}` - client names could be high cardinality
- Recommendation: Consider hashing client names or grouping clients

**Impact**:
- Memory: Each series consumes memory for indexing
- Query: More series = slower queries
- Storage: More data to store

**Mitigation**:
```go
// GOOD: Use bounded label values
typeLabel := map[qtype]string{
    dns.TypeA:      "A",
    dns.TypeAAAA:   "AAAA",
    dns.TypeTXT:    "TXT",
    // etc.
}

// Or group clients
clientGroup := getClientGroup(request.ClientNames) // Maps to small set of groups
```

---

### 2.2 Global Registry in Test Code

**Anti-Pattern**: Using global registry in unit tests

**Bad Example**:
```go
func TestResolver(t *testing.T) {
    resolver := NewResolver() // Registers with global metrics.Reg
    
    // ... test code ...
    
    // Multiple tests cause "duplicate metric registration" errors
}
```

**Evidence** ([Prometheus Users Discussion](https://groups.google.com/g/prometheus-users/c/OBi78vRYWok)):
> When I put my handler under test, I typically create a handler per test. This causes me to bump into "duplicate metrics collector registration attempted."

**Good Example**:
```go
func TestResolver(t *testing.T) {
    reg := prometheus.NewRegistry() // Fresh registry per test
    
    resolver := NewResolver(WithRegisterer(reg))
    
    // ... test code ...
    
    // No conflicts between tests
}
```

**Current Blocky Risk**:
- `resolver/metrics_resolver.go` registers metrics in `registerMetrics()` using global `metrics.Reg`
- Tests would have duplicate registration issues

---

### 2.3 Testing Metric Values Directly

**Anti-Pattern**: Verifying metric values in unit tests

**Bad Example**:
```go
func TestResolver(t *testing.T) {
    resolver := NewResolver()
    
    resolver.Resolve(ctx, req)
    
    // BAD: Testing instrumentation library, not your code
    metric := getMetricValue("resolver_queries_total")
    if metric != 1 {
        t.Errorf("expected 1, got %d", metric)
    }
}
```

**Evidence** ([Prometheus testutil Docs](https://pkg.go.dev/github.com/prometheus/client_golang/prometheus/testutil)):
> Rather than verifying that a prometheus.Counter's value has changed as expected, it is in general more robust and more faithful to the concept of unit tests to use mock implementations of the prometheus.Counter and prometheus.Registerer interfaces.

**Good Example**:
```go
// Mock counter interface
type MockCounter struct {
    AddCalled bool
    Value    float64
}

func (m *MockCounter) Add(v float64) {
    m.AddCalled = true
    m.Value += v
}

// Test logic, not metrics
func TestResolver(t *testing.T) {
    mockCounter := &MockCounter{}
    resolver := NewResolver(WithCounter(mockCounter))
    
    resolver.Resolve(ctx, req)
    
    if !mockCounter.AddCalled {
        t.Error("counter not incremented")
    }
}
```

---

### 2.4 Using promauto Without Custom Registry

**Anti-Pattern**: Using `promauto` with default registry

**Bad Example**:
```go
// BAD: Registers with global default registry
queries := promauto.NewCounter(prometheus.CounterOpts{
    Name: "queries_total",
    Help: "Total queries",
})
```

**Good Example**:
```go
// GOOD: Explicit registration with custom registry
reg := prometheus.NewRegistry()
queries := prometheus.NewCounter(prometheus.CounterOpts{
    Name: "queries_total",
    Help: "Total queries",
})
reg.MustRegister(queries)

// Or use promauto with custom registry
queries := promauto.With(reg).NewCounter(prometheus.CounterOpts{
    Name: "queries_total",
    Help: "Total queries",
})
```

**Evidence** ([Kubernetes Registry Pattern](https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/component-base/metrics/registry.go#L337)):
```go
func newKubeRegistry(v apimachineryversion.Info) *kubeRegistry {
    r := &kubeRegistry{
        PromRegistry: prometheus.NewRegistry(),
        // ...
    }
    return r
}
```

---

### 2.5 Gauges for Monotonic Values

**Anti-Pattern**: Using gauges for values that only increase

**Bad Example**:
```go
// BAD: Total requests should be a counter
totalRequests := prometheus.NewGauge(prometheus.GaugeOpts{
    Name: "total_requests",
    Help: "Total number of requests",
})
totalRequests.Inc() // Wrong pattern!
```

**Good Example**:
```go
// GOOD: Use counter for monotonic values
totalRequests := prometheus.NewCounter(prometheus.CounterOpts{
    Name: "total_requests",
    Help: "Total number of requests",
})
totalRequests.Inc() // Correct pattern!
```

**Evidence** ([Counter Best Practices](https://oneuptime.com/blog/post/2026-01-30-prometheus-counter-best-practices/view)):
> Do NOT use counters for: Values that can decrease, Request latency (use histogram), Memory usage (use gauge), Current queue depth (use gauge).

---

## 3. Testing Strategies

### 3.1 Interface-Based Mocking

**Strategy**: Mock `prometheus.Counter`, `prometheus.Gauge`, `prometheus.Histogram` interfaces

**Example**:
```go
type MockMetrics struct {
    CounterCalled  bool
    CounterValue  float64
    HistogramCalled bool
    HistogramValue  float64
}

func (m *MockMetrics) Inc() {
    m.CounterCalled = true
    m.CounterValue++
}

func (m *MockMetrics) Observe(v float64) {
    m.HistogramCalled = true
    m.HistogramValue = v
}

func TestResolver(t *testing.T) {
    mock := &MockMetrics{}
    resolver := NewResolver(WithMetrics(mock))
    
    resp, err := resolver.Resolve(ctx, req)
    
    Expect(mock.CounterCalled).To(BeTrue())
    Expect(mock.HistogramCalled).To(BeTrue())
}
```

**Evidence** ([Prometheus testutil Docs](https://pkg.go.dev/github.com/prometheus/client_golang/prometheus/testutil)):
> Use mock implementations of the prometheus.Counter and prometheus.Registerer interfaces that simply assert that the Add or Register methods have been called with the expected args.

**Pros**:
- Tests logic, not metrics
- Fast (no registry operations)
- No duplicate registration issues

**Cons**:
- Need to create mocks for each metric type
- Doesn't verify actual metric values (by design)

---

### 3.2 testutil for Integration Tests

**Strategy**: Use `prometheus/testutil` for integration/verification tests

**Example**:
```go
import "github.com/prometheus/client_golang/prometheus/testutil"

func TestMetricsIntegration(t *testing.T) {
    reg := prometheus.NewRegistry()
    metrics := NewMetrics(reg)
    
    // Exercise code
    metrics.RecordQuery("client1", "A")
    metrics.RecordQuery("client2", "AAAA")
    
    // Verify metrics
    err := testutil.GatherAndCompare(reg, strings.NewReader(`
        # HELP resolver_queries_total Total queries processed
        # TYPE resolver_queries_total counter
        resolver_queries_total{resolver="blocking",type="A"} 1
        resolver_queries_total{resolver="blocking",type="AAAA"} 1
    `), "resolver_queries_total")
    
    Expect(err).To(BeNil())
}
```

**Evidence** ([testutil.CollectAndCount PR](https://github.com/prometheus/client_golang/pull/703)):
> I would like to propose additional function to `testutil.go` which will count metrics in a given Collector.

**Available Functions**:
- `testutil.CollectAndCount(c prometheus.Collector) int` - Count metrics
- `testutil.CollectAndFormat(c, format, metricNames...)` - Format metrics
- `testutil.GatherAndCompare(g, expected, metricNames...)` - Compare metrics
- `testutil.ScrapeAndCompare(url, expected, metricNames...)` - Scrape HTTP endpoint

**Pros**:
- Verifies actual metric structure
- Catches registration issues
- Good for smoke tests

**Cons**:
- Slower than mocks
- Tests instrumentation, not logic
- Brittle: metric format changes break tests

**Use Cases**:
- Integration tests (verify metrics are exposed)
- Smoke tests (verify metrics after refactor)
- NOT unit tests (use mocks instead)

---

### 3.3 Separate Test Registries

**Strategy**: Create fresh registry for each test or test suite

**Example**:
```go
func TestMetricsResolver(t *testing.T) {
    t.Run("records query count", func(t *testing.T) {
        reg := prometheus.NewRegistry() // Isolated per test
        resolver := NewMetricsResolver(WithRegisterer(reg))
        
        resolver.Resolve(ctx, req)
        
        count := testutil.CollectAndCount(reg)
        Expect(count).To(Equal(4)) // queries, response, errors, duration
    })
    
    t.Run("records errors", func(t *testing.T) {
        reg := prometheus.NewRegistry() // Fresh registry
        resolver := NewMetricsResolver(WithRegisterer(reg))
        
        // ... force error ...
        
        err := testutil.GatherAndCompare(reg, expected, "blocky_error_total")
        Expect(err).To(BeNil())
    })
}
```

**Pros**:
- No test interference
- Clean state per test
- Can test different metric configurations

**Cons**:
- Slightly more setup code
- Need to manage registry lifecycle

---

### 3.4 Table-Driven Tests for Metric Labels

**Strategy**: Use table-driven tests for label combinations

**Example**:
```go
func TestMetricLabels(t *testing.T) {
    tests := []struct {
        name    string
        client  string
        qtype   uint16
        expect  string
    }{
        {
            name:   "A query",
            client: "client1",
            qtype:  dns.TypeA,
            expect: `queries_total{client="client1",type="A"} 1`,
        },
        {
            name:   "AAAA query",
            client: "client2",
            qtype:  dns.TypeAAAA,
            expect: `queries_total{client="client2",type="AAAA"} 1`,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            reg := prometheus.NewRegistry()
            metrics := NewMetrics(reg)
            
            metrics.RecordQuery(tt.client, tt.qtype)
            
            expected := strings.NewReader(fmt.Sprintf(`
                # HELP queries_total Total queries processed
                # TYPE queries_total counter
                %s
            `, tt.expect))
            
            err := testutil.GatherAndCompare(reg, expected, "queries_total")
            Expect(err).To(BeNil())
        })
    }
}
```

**Pros**:
- Easy to add new test cases
- Clear test intent
- Good for regression testing

---

## 4. Migration Strategies

### 4.1 Migrating from Global to Dependency Injection

**Step 1**: Add `prometheus.Registerer` to constructor
```go
// OLD
func NewMetricsResolver(cfg config.Metrics) *MetricsResolver

// NEW
func NewMetricsResolver(cfg config.Metrics, reg prometheus.Registerer) *MetricsResolver
```

**Step 2**: Update registration
```go
// OLD
func (r *MetricsResolver) registerMetrics() {
    metrics.RegisterMetric(r.durationHistogram)
    metrics.RegisterMetric(r.totalQueries)
    // ...
}

// NEW
func (r *MetricsResolver) registerMetrics(reg prometheus.Registerer) {
    reg.MustRegister(r.durationHistogram)
    reg.MustRegister(r.totalQueries)
    // ...
}
```

**Step 3**: Update call sites
```go
// OLD
metricsResolver := NewMetricsResolver(cfg.Metrics)

// NEW (production)
metricsResolver := NewMetricsResolver(cfg.Metrics, metrics.Reg)

// NEW (tests)
reg := prometheus.NewRegistry()
metricsResolver := NewMetricsResolver(cfg.Metrics, reg)
```

**Step 4**: Backward compatibility (optional)
```go
func NewMetricsResolver(cfg config.Metrics, reg ...prometheus.Registerer) *MetricsResolver {
    registerer := metrics.Reg
    if len(reg) > 0 {
        registerer = reg[0]
    }
    // ... use registerer
}
```

---

### 4.2 Migrating from Direct Access to Methods

**Step 1**: Add recording methods
```go
type MetricsResolver struct {
    // ... existing fields ...
}

// Add methods
func (r *MetricsResolver) recordQuery(client string, qtype uint16) {
    r.totalQueries.WithLabelValues(client, dns.TypeToString[qtype]).Inc()
}

func (r *MetricsResolver) recordDuration(rtype string, duration time.Duration) {
    r.durationHistogram.WithLabelValues(rtype).Observe(duration.Seconds())
}
```

**Step 2**: Update Resolve to use methods
```go
// OLD
r.totalQueries.With(prometheus.Labels{
    "client": strings.Join(request.ClientNames, ","),
    "type":   dns.TypeToString[request.Req.Question[0].Qtype],
}).Inc()

// NEW
r.recordQuery(strings.Join(request.ClientNames, ","), request.Req.Question[0].Qtype)
```

**Step 3**: Extract metrics struct for testing
```go
type ResolverMetrics interface {
    RecordQuery(client string, qtype uint16)
    RecordDuration(rtype string, duration time.Duration)
}

type MetricsResolver struct {
    metrics ResolverMetrics
    // ... other fields
}

func (r *MetricsResolver) Resolve(ctx context.Context, req *model.Request) (*model.Response, error) {
    // ... resolver logic ...
    r.metrics.RecordQuery(client, qtype)
    // ...
}
```

---

### 4.3 Reducing Label Cardinality

**Step 1**: Identify high-cardinality labels
```bash
# Check cardinality
curl http://localhost:4000/metrics | grep "blocky_query_total{" | wc -l

# Find high-cardinality labels
curl http://localhost:4000/metrics | grep "blocky_query_total{" | cut -d'{' -f2 | cut -d'}' -f1 | sort | uniq -c | sort -rn
```

**Step 2**: Group or hash label values
```go
// OLD: High cardinality
r.totalQueries.WithLabelValues(
    strings.Join(request.ClientNames, ","), // Can be many unique values
    dns.TypeToString[qtype],
).Inc()

// NEW: Group clients
func getClientGroup(clientNames []string) string {
    // Hash or group to reduce cardinality
    if len(clientNames) > 5 {
        return "many_clients"
    }
    return strings.Join(clientNames, ",")
}

r.totalQueries.WithLabelValues(
    getClientGroup(request.ClientNames),
    dns.TypeToString[qtype],
).Inc()
```

**Step 3**: Use consistent hashing
```go
import "github.com/mitchellh/hashstructure/v2"

func hashClient(clientNames []string) string {
    h, _ := hashstructure.Hash(clientNames, hashstructure.FormatV2, nil)
    return fmt.Sprintf("client_%d", h%100) // Max 100 unique values
}
```

---

## 5. Specific Recommendations for Chain-of-Responsibility + Metrics

### 5.1 Pattern: Metrics as Chain Middleware

**Current Blocky Implementation**: ✅ ALREADY FOLLOWS THIS PATTERN

```go
type MetricsResolver struct {
    configurable[*config.Metrics]
    NextResolver
    // metrics fields
}

func (r *MetricsResolver) Resolve(ctx context.Context, req *model.Request) (*model.Response, error) {
    response, err := r.next.Resolve(ctx, request)
    
    if r.cfg.Enable {
        // Record metrics after resolution
        r.totalQueries.WithLabelValues(client, qtype).Inc()
        r.durationHistogram.WithLabelValues(responseType).Observe(duration)
    }
    
    return response, err
}
```

**Assessment**: This is the **correct pattern** for chain-of-responsibility. Metrics resolver wraps the chain and records after each resolution.

---

### 5.2 Recommendation: Extract Metrics Interface

**Problem**: Metrics are tightly coupled to `prometheus` types, making testing difficult.

**Solution**: Extract interface for metrics recording

```go
// metrics.go
package metrics

type ResolverMetrics interface {
    RecordQuery(client string, qtype uint16)
    RecordResponse(rtype, code, reason string, duration time.Duration)
    RecordError()
}

type PrometheusResolverMetrics struct {
    queries      *prometheus.CounterVec
    responses    *prometheus.CounterVec
    errors       prometheus.Counter
    duration     *prometheus.HistogramVec
}

func NewResolverMetrics(reg prometheus.Registerer) *PrometheusResolverMetrics {
    m := &PrometheusResolverMetrics{
        queries: prometheus.NewCounterVec(
            prometheus.CounterOpts{
                Name: "blocky_query_total",
                Help: "Number of total queries",
            },
            []string{"client", "type"},
        ),
        // ... other metrics ...
    }
    
    reg.MustRegister(m.queries, m.responses, m.errors, m.duration)
    return m
}

func (m *PrometheusResolverMetrics) RecordQuery(client string, qtype uint16) {
    m.queries.WithLabelValues(client, dns.TypeToString[qtype]).Inc()
}

func (m *PrometheusResolverMetrics) RecordResponse(rtype, code, reason string, duration time.Duration) {
    m.responses.WithLabelValues(reason, code, rtype).Inc()
    m.duration.WithLabelValues(rtype).Observe(duration.Seconds())
}

func (m *PrometheusResolverMetrics) RecordError() {
    m.errors.Inc()
}
```

**Benefits**:
- Testable: Can create mock metrics
- Flexible: Can swap implementations
- SOLID: Dependency Inversion Principle

---

### 5.3 Recommendation: Resolver Chain Metrics

**Pattern**: Track metrics at chain level, not just individual resolvers

```go
type ChainMetrics struct {
    totalDuration *prometheus.HistogramVec
    resolverHits  *prometheus.CounterVec
    cacheHits     *prometheus.CounterVec
}

func NewChainMetrics(reg prometheus.Registerer) *ChainMetrics {
    m := &ChainMetrics{
        totalDuration: prometheus.NewHistogramVec(
            prometheus.HistogramOpts{
                Name:    "blocky_chain_duration_seconds",
                Help:    "Total time through resolver chain",
                Buckets: prometheus.DefBuckets,
            },
            []string{"resolver_chain"},
        ),
        resolverHits: prometheus.NewCounterVec(
            prometheus.CounterOpts{
                Name: "blocky_resolver_hits_total",
                Help: "Number of times each resolver was called",
            },
            []string{"resolver"},
        ),
        cacheHits: prometheus.NewCounterVec(
            prometheus.CounterOpts{
                Name: "blocky_cache_hits_total",
                Help: "Number of cache hits per resolver",
            },
            []string{"resolver"},
        ),
    }
    
    reg.MustRegister(m.totalDuration, m.resolverHits, m.cacheHits)
    return m
}
```

**Benefits**:
- See which resolvers are hot paths
- Identify bottlenecks in chain
- Optimize chain ordering

---

### 5.4 Recommendation: Conditional Metrics Recording

**Pattern**: Only record metrics when enabled (already implemented ✅)

```go
func (r *MetricsResolver) Resolve(ctx context.Context, req *model.Request) (*model.Response, error) {
    start := time.Now()
    response, err := r.next.Resolve(ctx, request)
    
    if r.cfg.Enable {  // ✅ Already implemented
        // Record metrics
    }
    
    return response, err
}
```

**Assessment**: ✅ GOOD - Blocky already has this pattern

---

### 5.5 Recommendation: Label Cardinality Management

**Risk**: `client` label in `blocky_query_total` could have high cardinality

**Mitigation**:
```go
// Option 1: Hash client names
import "crypto/sha256"

func hashClientNames(clientNames []string) string {
    if len(clientNames) == 0 {
        return "unknown"
    }
    
    joined := strings.Join(clientNames, ",")
    h := sha256.Sum256([]byte(joined))
    return fmt.Sprintf("client_%x", h[:4]) // Use first 4 bytes
}

// Option 2: Group clients
func getClientGroup(clientNames []string) string {
    switch {
    case len(clientNames) == 0:
        return "unknown"
    case len(clientNames) == 1:
        return clientNames[0]
    case len(clientNames) > 10:
        return "many_clients"
    default:
        return strings.Join(clientNames, ",")
    }
}

// Option 3: Client groups from config
func getClientGroupFromConfig(clientNames []string, cfg *config.Config) string {
    for name, group := range cfg.ClientGroups {
        for _, client := range clientNames {
            if contains(group.Clients, client) {
                return name
            }
        }
    }
    return "default"
}
```

---

### 5.6 Recommendation: Standardize Metrics Naming

**Pattern**: Follow Prometheus naming conventions

**Current Blocky Metrics** (from code):
- `blocky_query_total` ✅ Good
- `blocky_error_total` ✅ Good
- `blocky_response_total` ✅ Good
- `blocky_request_duration_seconds` ✅ Good
- `blocky_build_info` ✅ Good
- `blocky_blocking_enabled` ✅ Good
- `blocky_denylist_cache_entries` ✅ Good
- `blocky_allowlist_cache_entries` ✅ Good
- `blocky_cache_entries` ✅ Good
- `blocky_prefetches_total` ✅ Good
- `blocky_prefetch_hits_total` ✅ Good
- `blocky_failed_downloads_total` ✅ Good

**Assessment**: ✅ EXCELLENT - All metrics follow naming conventions

**Naming Convention** (from [Prometheus Best Practices](https://prometheus.io/docs/practices/naming/)):
```
[metric_namespace]_[metric_name]_[unit]
                    unit: seconds, bytes, total
```

Blocky follows this perfectly!

---

## 6. Conclusion

### 6.1 Current Blocky Metrics Implementation Assessment

**Strengths** ✅:
- Uses custom registry (`metrics.Reg`)
- Metrics as resolver middleware (chain-of-responsibility pattern)
- Conditional metrics recording
- Native histograms for better resolution
- Excellent naming conventions
- Event-driven metrics via event bus

**Areas for Improvement** ⚠️:
- No dependency injection (uses global `metrics.Reg`)
- Metrics not extractable for testing
- Potential label cardinality issues with `client` names
- Tests would have duplicate registration issues

---

### 6.2 Priority Recommendations

**High Priority**:
1. Add `prometheus.Registerer` to resolver constructors (enables testing)
2. Extract metrics interface (enables mocking)
3. Add `testutil` integration tests for metrics verification
4. Consider client name grouping to reduce cardinality

**Medium Priority**:
5. Add chain-level metrics (total duration, resolver hits)
6. Create table-driven tests for label combinations
7. Document metrics in docs/config.yml

**Low Priority**:
8. Add exemplar support for distributed tracing
9. Consider adding percentiles to histograms

---

### 6.3 Migration Path

**Phase 1**: Enable Testing (High Priority)
- Add optional `prometheus.Registerer` parameter
- Keep backward compatibility
- Add mock metrics for tests

**Phase 2**: Improve Observability (Medium Priority)
- Add chain-level metrics
- Add resolver hit tracking
- Create Grafana dashboards

**Phase 3**: Optimize (Low Priority)
- Review label cardinality
- Add exemplars
- Consider advanced features

---

## References

### Official Documentation
- [Prometheus Go Client](https://prometheus.io/docs/guides/go-application/)
- [Prometheus Client Libraries](https://prometheus.io/docs/instrumenting/clientlibs/)
- [Prometheus Naming Best Practices](https://prometheus.io/docs/practices/naming/)
- [Prometheus Instrumentation Best Practices](https://prometheus.io/docs/practices/instrumentation/)

### Community Articles (2026)
- [How to Create Custom Metrics in Go with Prometheus](https://oneuptime.com/blog/post/2026-01-07-go-prometheus-custom-metrics/view)
- [How to Build a Prometheus Client in Go](https://oneuptime.com/blog/post/2026-01-30-go-prometheus-client/view)
- [How to Manage Metric Cardinality in Prometheus](https://oneuptime.com/blog/post/2026-01-25-prometheus-metric-cardinality/view)
- [How to Follow Label Best Practices in Prometheus](https://oneuptime.com/blog/post/2026-01-27-prometheus-label-best-practices/view)
- [How to Implement Prometheus Counter Best Practices](https://oneuptime.com/blog/post/2026-01-30-prometheus-counter-best-practices/view)

### Code Examples
- [Kubernetes Registry](https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/component-base/metrics/registry.go)
- [Prometheus testutil Package](https://pkg.go.dev/github.com/prometheus/client_golang/prometheus/testutil)
- [Prometheus Client Examples](https://github.com/prometheus/client_golang/blob/main/prometheus/examples_test.go)

### Design Patterns
- [Chain of Responsibility for Request Handling](https://www.momentslog.com/development/web-backend/using-the-chain-of-responsibility-pattern-for-request-handling-in-web-apis-implementing-middleware)
- [Middleware Chains in Go HTTP Servers](https://oneuptime.com/blog/post/2026-01-30-go-middleware-chains-http/view)
- [Mastering Design Patterns in Go Network Programming](https://dev.to/jones_charles_ad50858dbc0/mastering-design-patterns-in-go-network-programming-a-practical-guide-1b6h)

### SOLID Principles
- [OpenTelemetry Metrics Custom Instruments](https://oneuptime.com/blog/post/2026-02-06-build-custom-opentelemetry-metric-instruments-go/view)
- [OpenTelemetry Instrumentation Guide](https://oneuptime.com/blog/post/2026-02-20-go-opentelemetry-instrumentation/view)

---

**End of Report**
