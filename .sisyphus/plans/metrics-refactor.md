# Metrics and Lifecycle Refactoring Work Plan

**Plan Name**: metrics-refactor  
**Created**: 2026-03-13  
**Goal**: Unify metrics emission patterns, remove event bus for lifecycle, apply SOLID principles

---

## Executive Summary

### Goals
1. **Remove lifecycle event bus dependency**: Replace `ApplicationStarted` event with explicit `PostStarter` interface
2. **Unify metrics patterns**: Remove event bus for metrics, use consistent direct Prometheus emission
3. **Eliminate global state**: Remove or properly inject `evt.Bus()` and `metrics.Reg` globals
4. **Improve testability**: Make lifecycle and metrics dependencies explicit and injectable
5. **Maintain compatibility**: Zero breaking changes to external APIs or configuration

### Scope

**IN SCOPE:**
- PostStarter interface for resolver lifecycle hooks
- BlockingResolver FQDN cache initialization refactor
- Metrics event bus removal (8 metrics-related events)
- ApplicationStarted event removal
- Direct Prometheus metrics emission unified pattern
- Test updates for lifecycle and metrics

**OUT OF SCOPE:**
- Redis cross-instance sync (uses separate channel pattern, not event bus)
- Event bus subscriber for redis (uses Go channels, separate from lifecycle)
- Changes to external APIs or configuration format
- Performance optimization beyond maintaining current performance
- New features or functionality

### Success Metrics
- ✅ All tests pass (`make test`)
- ✅ E2E tests pass (`make e2e-test`)
- ✅ Lint clean (`make lint`)
- ✅ Build succeeds (`make build`)
- ✅ All Prometheus metrics still emit correctly
- ✅ BlockingResolver FQDN cache initializes properly
- ✅ Zero global event bus usage for lifecycle/metrics (Redis sync excluded)
- ✅ Code coverage maintained or improved

---

## Phase 1: Lifecycle Refactoring (PostStarter Interface)

**Goal**: Replace `ApplicationStarted` event with explicit `PostStarter` interface

### Tasks

- [x] **L1.1: Add PostStarter interface to resolver package**
  - **Files**: `resolver/resolver.go` (after line 30, near other interfaces)
  - **Changes**: 
    - Add `PostStarter` interface with `PostStart(ctx context.Context) error`
    - Add comprehensive godoc explaining when PostStart is called
    - Document that it's called AFTER DNS listeners are up
  - **Parallelizable**: No (foundation for other tasks)
  - **Dependencies**: None
  - **Verification**: 
    - `make lint` succeeds
    - `make build` succeeds
    - Interface compiles without errors
  - **Risk**: Low (interface addition is non-breaking)
  - **Expected Code**:
    ```go
    // PostStarter is an optional interface that resolvers can implement
    // to perform initialization that requires the DNS server to be running.
    //
    // Example: BlockingResolver needs to perform DNS lookups to initialize
    // its FQDN IP cache, which requires upstream resolvers to be operational.
    //
    // PostStart is called by server.Start() after all DNS listeners are up.
    type PostStarter interface {
        PostStart(ctx context.Context) error
    }
    ```

- [x] **L1.2: Implement PostStart on BlockingResolver**
  - **Files**: `resolver/blocking_resolver.go`
  - **Changes**:
    - Add `PostStart(ctx context.Context) error` method
    - Move logic from `initFQDNIPCache()` (lines 625-634) into PostStart
    - Add logging (debug level): "initializing FQDN IP cache" at start
    - Add logging (debug level): "FQDN IP cache initialized with X entries" at end
    - Keep `initFQDNIPCache()` private method, call it from PostStart
  - **Parallelizable**: No
  - **Dependencies**: L1.1
  - **Verification**:
    - `make lint` clean
    - Method signature matches PostStarter interface
    - Logic correctly initializes FQDN cache
  - **Risk**: Medium (DNS lookups must work correctly)
  - **Expected Code**:
    ```go
    // PostStart initializes the FQDN IP cache by performing DNS lookups.
    // This must run after the DNS server is fully operational because it
    // needs to resolve FQDNs using the upstream resolvers.
    func (r *BlockingResolver) PostStart(ctx context.Context) error {
        ctx, logger := r.log(ctx)
        logger.Debug("initializing FQDN IP cache")
        
        r.initFQDNIPCache(ctx)
        
        identifiers := maps.Keys(r.clientGroupsBlock)
        fqdnCount := 0
        for _, id := range identifiers {
            if isFQDN(id) {
                fqdnCount++
            }
        }
        logger.Debugf("FQDN IP cache initialized with %d entries", fqdnCount)
        return nil
    }
    ```

- [x] **L1.3: Call PostStart hooks in server.Start()**
  - **Files**: `server/server.go`
  - **Changes**:
    - In `Start()` method (around line 440-470), after DNS listeners start
    - Add code to iterate resolver chain using `resolver.ForEach()`
    - Type-assert each resolver to `resolver.PostStarter`
    - Call `PostStart(ctx)` if implemented
    - Log warning if PostStart fails (don't fail server startup)
  - **Parallelizable**: No
  - **Dependencies**: L1.1, L1.2
  - **Verification**:
    - `make lint` clean
    - Code correctly iterates chain using existing ForEach pattern
    - Error handling logs warnings but continues
  - **Risk**: Medium (must call after DNS listeners, not before)
  - **Expected Code Location**: After line 467 (after DNS servers start)
  - **Expected Code**:
    ```go
    // Call PostStart hooks on resolvers after DNS listeners are up
    logger().Debug("calling PostStart hooks on resolver chain")
    resolver.ForEach(s.queryResolver, func(res resolver.Resolver) {
        if ps, ok := res.(resolver.PostStarter); ok {
            if err := ps.PostStart(ctx); err != nil {
                logger().Warnf("PostStart failed for %s: %v", res.Type(), err)
                // Don't fail server startup - log and continue
            }
        }
    })
    ```

- [x] **L1.4: Remove ApplicationStarted event subscription from BlockingResolver**
  - **Files**: `resolver/blocking_resolver.go`
  - **Changes**:
    - Delete lines 168-173 (event subscription in NewBlockingResolver)
    - Remove import of `evt` package if no longer needed
  - **Parallelizable**: No
  - **Dependencies**: L1.3 (must have PostStart working first)
  - **Verification**:
    - `make lint` clean
    - `make build` succeeds
    - Resolver no longer subscribes to ApplicationStarted
  - **Risk**: Low (replaced by PostStart)
  - **Lines to DELETE**:
    ```go
    err = evt.Bus().SubscribeOnce(evt.ApplicationStarted, func(_ ...string) {
        go res.initFQDNIPCache(ctx)
    })
    if err != nil {
        return nil, fmt.Errorf("failed to subscribe to ApplicationStarted event: %w", err)
    }
    ```

- [x] **L1.5: Remove ApplicationStarted event publish from cmd/serve.go**
  - **Files**: `cmd/serve.go`
  - **Changes**:
    - Delete line 89 (`evt.Bus().Publish(evt.ApplicationStarted)`)
    - Remove import of `evt` package if no longer needed
  - **Parallelizable**: No
  - **Dependencies**: L1.4
  - **Verification**:
    - `make lint` clean
    - `make build` succeeds
    - ApplicationStarted event no longer published
  - **Risk**: Low

- [x] **L1.6: Remove ApplicationStarted event constant from evt/events.go**
  - **Files**: `evt/events.go`
  - **Changes**:
    - Delete `ApplicationStarted = "application:started"` constant
    - Check if file is still needed (other events exist)
  - **Parallelizable**: No
  - **Dependencies**: L1.4, L1.5
  - **Verification**:
    - `make lint` clean
    - `grep -r "ApplicationStarted" .` returns zero results (except tests)
  - **Risk**: Low

- [x] **L1.7: Update BlockingResolver tests**
  - **Files**: `resolver/blocking_resolver_test.go`
  - **Changes**:
    - Find test that publishes ApplicationStarted (around line 148)
    - Replace event publish with direct `PostStart()` call
    - Add new test: "PostStart initializes FQDN IP cache"
    - Verify FQDN cache contains expected entries after PostStart
  - **Parallelizable**: No
  - **Dependencies**: L1.2
  - **Verification**:
    - `make test` passes
    - New test covers PostStart behavior
    - Test no longer depends on event bus
  - **Risk**: Low
  - **Expected Test**:
    ```go
    When("PostStart is called", func() {
        It("should initialize FQDN IP cache for FQDN identifiers", func(ctx context.Context) {
            // Setup: resolver with FQDN identifier
            cfg := &config.BlockingConfig{
                ClientGroupsBlock: map[string][]string{
                    "client1.example.com": {"ads"},
                },
            }
            mockUpstream := // ... mock that returns IPs
            r := NewBlockingResolver(ctx, cfg, nil, mockUpstream)
            
            // Execute
            err := r.PostStart(ctx)
            
            // Verify
            Expect(err).Should(Succeed())
            Expect(r.fqdnIPCache.Len()).Should(BeNumerically(">", 0))
        })
    })
    ```

- [x] **L1.8: Add integration test for server lifecycle**
  - **Files**: `server/server_test.go`
  - **Changes**:
    - Add test: "Start should call PostStart on resolvers"
    - Create mock resolver implementing PostStarter
    - Start server, verify PostStart was called
  - **Parallelizable**: No
  - **Dependencies**: L1.3
  - **Verification**:
    - `make test` passes
    - Test verifies PostStart called after server starts
  - **Risk**: Low

### Phase 1 Verification

**Unit Tests:**
```bash
# Run resolver tests
go test ./resolver/... -v

# Check for PostStarter implementation
grep -r "func.*PostStart.*context.Context.*error" resolver/
```

**Integration Tests:**
```bash
# Run server tests
go test ./server/... -v
```

**Manual Tests:**
```bash
# Start blocky with config that has FQDN client identifiers
cat > test-config.yml <<EOF
blocking:
  clientGroupsBlock:
    client1.example.com:
      - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
    192.168.1.1:
      - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
EOF

# Build and run
make build
./bin/blocky serve -c test-config.yml

# Check logs for "initializing FQDN IP cache"
# Check logs for "FQDN IP cache initialized with X entries"
# Verify no errors about ApplicationStarted event
```

**Expected Behavior:**
- Server starts successfully
- Logs show "initializing FQDN IP cache" at debug level
- Logs show "FQDN IP cache initialized with X entries"
- No errors or warnings about missing events
- BlockingResolver blocks domains correctly

**Success Criteria:**
- ✅ PostStarter interface exists in resolver package
- ✅ BlockingResolver implements PostStart
- ✅ Server.Start() calls PostStart after DNS listeners up
- ✅ ApplicationStarted event completely removed
- ✅ All tests pass
- ✅ FQDN cache initialization works correctly

---

## Phase 2: Metrics Refactoring

**Goal**: Remove event bus for metrics emission, unify to direct Prometheus pattern

### Background Analysis

**Current Metrics Events** (from `evt/events.go`):
1. `BlockingEnabledEvent` - when blocking is enabled/disabled
2. `BlockingCacheGroupChanged` - when blocking cache changes
3. `CachingResultCacheChanged` - when caching size changes
4. `CachingDomainsToPrefetchCountChanged` - when prefetch count changes
5. `CachingPrefetchCacheChanged` - when prefetch cache changes
6. `ApplicationStarted` - (removing in Phase 1)
7. Additional metrics events published by resolvers

**Current Metrics Emission Patterns:**

**Pattern A: Direct Prometheus** (preferred, already used):
- `resolver/metrics_resolver.go` - direct calls to Prometheus
- `resolver/dnssec/validator.go` - direct metrics
- `resolver/caching_resolver.go` - package-level `promauto` metrics

**Pattern B: Event Bus Indirection** (to remove):
- Resolvers publish events → `metrics/metrics_event_publisher.go` subscribes → updates Prometheus
- Adds complexity, no benefits

### Tasks

- [x] **M2.1: Audit all metrics event publishers**
  - **Files**: Use `grep` to find all event publishers
  - **Changes**: None (analysis only)
  - **Command**: 
    ```bash
    grep -r "evt.Bus().Publish" --include="*.go" | grep -v "_test.go"
    grep -r "BlockingEnabled\|CachingResultCacheChanged\|CachingDomainsToPrefetchCountChanged" --include="*.go"
    ```
  - **Parallelizable**: Yes
  - **Dependencies**: None
  - **Verification**: Document all locations that publish metrics events
  - **Risk**: Low (read-only analysis)
  - **Deliverable**: List of files and line numbers that publish metrics events

- [x] **M2.2: Add direct Prometheus metrics to BlockingResolver**
  - **Files**: `resolver/blocking_resolver.go`
  - **Changes**:
    - Add package-level Prometheus gauge for blocking enabled/disabled status
    - Add package-level Prometheus gauge for cache group sizes
    - Update `EnableBlocking()` to directly update Prometheus gauge
    - Update `DisableBlocking()` to directly update Prometheus gauge
    - Remove event publish calls for BlockingEnabled
  - **Parallelizable**: No
  - **Dependencies**: M2.1
  - **Verification**:
    - `make lint` clean
    - Prometheus metrics endpoint shows metrics
    - Metrics update when blocking enabled/disabled
  - **Risk**: Medium (metrics must emit correctly)
  - **Expected Code Pattern** (follow existing `metrics_resolver.go` pattern):
    ```go
    var (
        blockingStatusMetric = promauto.NewGaugeVec(
            prometheus.GaugeOpts{
                Name: "blocky_blocking_enabled",
                Help: "Blocking status (1 = enabled, 0 = disabled)",
            },
            []string{"group"},
        )
    )
    
    func (r *BlockingResolver) EnableBlocking(ctx context.Context) {
        // ... existing logic ...
        blockingStatusMetric.WithLabelValues("default").Set(1)
        // REMOVE: evt.Bus().Publish(evt.BlockingEnabled, ...)
    }
    ```

- [x] **M2.3: Add direct Prometheus metrics to CachingResolver**
  - **Files**: `resolver/caching_resolver.go`
  - **Changes**:
    - Verify existing package-level metrics (already uses promauto)
    - Remove event publish calls for CachingResultCacheChanged, CachingDomainsToPrefetchCountChanged, CachingPrefetchCacheChanged
    - Ensure metrics update directly when cache changes
  - **Parallelizable**: No
  - **Dependencies**: M2.1
  - **Verification**:
    - Prometheus metrics endpoint shows cache metrics
    - Cache size metrics update correctly
  - **Risk**: Low (already uses direct Prometheus, just removing events)

- [x] **M2.4: Remove metrics_event_publisher.go subscribers**
  - **Files**: `metrics/metrics_event_publisher.go`
  - **Changes**:
    - Remove event subscriptions for BlockingEnabled
    - Remove event subscriptions for CachingResultCacheChanged
    - Remove event subscriptions for CachingDomainsToPrefetchCountChanged
    - Remove event subscriptions for CachingPrefetchCacheChanged
    - If file becomes empty, delete it
  - **Parallelizable**: No
  - **Dependencies**: M2.2, M2.3
  - **Verification**:
    - `make lint` clean
    - `make build` succeeds
    - File removed or significantly simplified
  - **Risk**: Low (subscribers no longer needed)

- [x] **M2.5: Remove metrics event constants from evt/events.go**
  - **Files**: `evt/events.go`
  - **Changes**:
    - Delete BlockingEnabledEvent constant
    - Delete BlockingCacheGroupChanged constant
    - Delete CachingResultCacheChanged constant
    - Delete CachingDomainsToPrefetchCountChanged constant
    - Delete CachingPrefetchCacheChanged constant
  - **Parallelizable**: No
  - **Dependencies**: M2.2, M2.3, M2.4
  - **Verification**:
    - `make lint` clean
    - `grep` confirms no usage of deleted constants
  - **Risk**: Low

- [x] **M2.6: Update metrics tests**
  - **Files**: `metrics/metrics_test.go`, resolver tests
  - **Changes**:
    - Remove tests that depend on event bus
    - Add tests that verify direct Prometheus metrics emission
    - Test BlockingResolver metrics update on Enable/Disable
    - Test CachingResolver metrics update on cache changes
  - **Parallelizable**: No
  - **Dependencies**: M2.2, M2.3
  - **Verification**:
    - `make test` passes
    - Tests verify direct metrics emission
  - **Risk**: Low

- [x] **M2.7: Add integration test for Prometheus metrics endpoint**
  - **Files**: New file `metrics/integration_test.go` or add to existing
  - **Changes**:
    - Start server with test config
    - Enable/disable blocking
    - Query Prometheus metrics endpoint (`/metrics`)
    - Verify blocking status metric present and correct
    - Verify cache metrics present and correct
  - **Parallelizable**: No
  - **Dependencies**: M2.2, M2.3
  - **Verification**:
    - Test passes
    - Metrics endpoint returns expected metrics
  - **Risk**: Medium (integration test setup can be complex)
  - **Expected Test**:
    ```go
    It("should expose blocking status metric", func(ctx context.Context) {
        // Start server
        server, _ := NewServer(ctx, testConfig)
        go server.Start(ctx, make(chan error))
        defer server.Stop(ctx)
        
        // Enable blocking
        server.EnableBlocking(ctx)
        
        // Query metrics endpoint
        resp, err := http.Get("http://localhost:4000/metrics")
        Expect(err).Should(Succeed())
        
        body, _ := io.ReadAll(resp.Body)
        Expect(string(body)).Should(ContainSubstring("blocky_blocking_enabled"))
        Expect(string(body)).Should(ContainSubstring("blocky_blocking_enabled{group=\"default\"} 1"))
    })
    ```

### Phase 2 Verification

**Unit Tests:**
```bash
# Run metrics tests
go test ./metrics/... -v

# Run resolver tests
go test ./resolver/... -v -run TestBlockingResolver
go test ./resolver/... -v -run TestCachingResolver
```

**Integration Tests:**
```bash
# Start blocky
make run

# In another terminal, query metrics endpoint
curl http://localhost:4000/metrics | grep blocky_blocking_enabled
curl http://localhost:4000/metrics | grep blocky_cache

# Enable/disable blocking via API
curl -X POST http://localhost:4000/api/blocking/enable
curl http://localhost:4000/metrics | grep blocky_blocking_enabled
# Should show 1

curl -X POST http://localhost:4000/api/blocking/disable
curl http://localhost:4000/metrics | grep blocky_blocking_enabled
# Should show 0
```

**Manual Tests:**
```bash
# Start blocky with Prometheus scraping
make run

# Use Prometheus to scrape metrics
# Or use curl to check metrics endpoint
curl -s http://localhost:4000/metrics | grep "^blocky_" | head -20

# Expected metrics (examples):
# blocky_blocking_enabled{group="default"} 1
# blocky_cache_entry_count{cache_type="result"} 42
# blocky_cache_hit_count 1234
# blocky_query_total{client="...",reason="...",response_type="..."} 567
```

**Expected Behavior:**
- All Prometheus metrics emit correctly
- Metrics update in real-time when state changes
- No event bus used for metrics
- `/metrics` endpoint returns expected format

**Success Criteria:**
- ✅ All metrics events removed from evt package
- ✅ metrics_event_publisher.go removed or empty
- ✅ BlockingResolver uses direct Prometheus
- ✅ CachingResolver uses direct Prometheus
- ✅ All metrics tests pass
- ✅ Integration test verifies metrics endpoint
- ✅ Manual curl test shows correct metrics

---

## Phase 3: Event Bus Cleanup

**Goal**: Remove event bus package if fully unused (Redis sync check)

### Tasks

- [ ] **E3.1: Audit remaining event bus usage**
  - **Files**: All `.go` files
  - **Command**:
    ```bash
    grep -r "evt.Bus()" --include="*.go" | grep -v "_test.go"
    grep -r "import.*evt" --include="*.go"
    ```
  - **Changes**: None (analysis only)
  - **Parallelizable**: Yes
  - **Dependencies**: Phase 1 and Phase 2 complete
  - **Verification**: Document all remaining evt.Bus() calls
  - **Risk**: Low (read-only)
  - **Expected Result**: Only Redis subscriber should remain (uses separate channel pattern)

- [ ] **E3.2: Verify Redis sync does NOT use event bus for core functionality**
  - **Files**: `resolver/blocking_resolver.go` (redisSubscriber method)
  - **Changes**: None (verification only)
  - **Command**: Read lines 178-200 (redisSubscriber method)
  - **Parallelizable**: Yes
  - **Dependencies**: E3.1
  - **Verification**: Confirm Redis uses Go channels, not event bus events
  - **Risk**: Low
  - **Expected Finding**: Redis subscriber uses `pubsub.Channel()` (Go channel), NOT `evt.Bus()`

- [ ] **E3.3: Remove evt package if fully unused**
  - **Files**: `evt/events.go`, `evt/` directory
  - **Changes**:
    - If E3.1 confirms zero usage: delete `evt/` directory
    - If Redis still uses it: keep evt package but document why
    - Remove `github.com/asaskevich/EventBus` from `go.mod` if possible
  - **Parallelizable**: No
  - **Dependencies**: E3.1, E3.2
  - **Verification**:
    - `make lint` clean
    - `make build` succeeds
    - `grep -r "evt\\.Bus" .` returns zero results
  - **Risk**: Low (if Phase 1 & 2 complete, should be safe)

- [ ] **E3.4: Update CLAUDE.md documentation**
  - **Files**: `CLAUDE.md`
  - **Changes**:
    - Remove references to event bus pattern
    - Document PostStarter lifecycle pattern
    - Document direct Prometheus metrics pattern
    - Update architecture notes
  - **Parallelizable**: Yes
  - **Dependencies**: E3.3
  - **Verification**: Documentation accurately reflects new architecture
  - **Risk**: Low

### Phase 3 Verification

**Verification Commands:**
```bash
# Confirm event bus fully removed (or only Redis remains)
grep -r "evt.Bus()" --include="*.go" | grep -v "_test.go" | wc -l
# Expected: 0 (or only Redis subscriber if kept)

grep -r "evt\\.Bus\\(\\)" . --include="*.go"
# Expected: Empty or only Redis-related

# Check go.mod
grep "EventBus" go.mod
# Expected: Removed if evt package deleted

# Build and test
make all
# Expected: Success
```

**Success Criteria:**
- ✅ Event bus package removed OR documented as Redis-only
- ✅ No lifecycle or metrics code uses event bus
- ✅ EventBus dependency removed from go.mod (if package deleted)
- ✅ CLAUDE.md updated
- ✅ All tests pass

---

## Phase 4: Final Verification Wave

**Goal**: Comprehensive verification that all changes work correctly

### Tasks

- [ ] **F4.1: Code Review Verification**
  - **Reviewer**: Manual review required
  - **Checklist**:
    - [ ] PostStarter interface clearly documented
    - [ ] BlockingResolver.PostStart correctly implements FQDN cache init
    - [ ] Server.Start calls PostStart at correct time (after DNS listeners)
    - [ ] All metrics emit via direct Prometheus (no event bus)
    - [ ] No global state violations (evt.Bus() removed for lifecycle/metrics)
    - [ ] Error handling appropriate (warnings for PostStart failures)
    - [ ] Code follows existing Blocky patterns (ForEach, optional interfaces)
    - [ ] No new dependencies added
  - **Verification**: Manual checklist completion
  - **Risk**: N/A

- [ ] **F4.2: Test Coverage Verification**
  - **Command**:
    ```bash
    # Run all tests
    make test
    
    # Run E2E tests
    make e2e-test
    
    # Check test coverage
    go test ./... -coverprofile=coverage.out
    go tool cover -func=coverage.out | grep -E "(resolver|metrics|server)"
    ```
  - **Verification**:
    - All unit tests pass
    - All integration tests pass
    - All E2E tests pass
    - Coverage maintained or improved for resolver, metrics, server packages
  - **Expected**: 0 failures, coverage ≥ current baseline
  - **Risk**: N/A

- [ ] **F4.3: Performance Verification**
  - **Command**:
    ```bash
    # Benchmark resolver chain
    go test ./resolver/... -bench=. -benchmem
    
    # Start server and measure query latency
    make run &
    for i in {1..1000}; do
      dig @localhost -p 53 example.com +noall +stats | grep "Query time"
    done
    ```
  - **Verification**:
    - No performance regressions in benchmarks
    - DNS query latency unchanged
    - Memory allocation similar to baseline
  - **Expected**: Performance within 5% of baseline
  - **Risk**: N/A

- [ ] **F4.4: Prometheus Metrics Verification**
  - **Command**:
    ```bash
    # Start blocky
    make run &
    
    # Wait for startup
    sleep 5
    
    # Query metrics endpoint
    curl -s http://localhost:4000/metrics > metrics.txt
    
    # Verify key metrics exist
    grep "blocky_blocking_enabled" metrics.txt
    grep "blocky_cache_entry_count" metrics.txt
    grep "blocky_query_total" metrics.txt
    grep "blocky_error_total" metrics.txt
    
    # Verify no errors in metrics output
    grep "error" metrics.txt
    ```
  - **Verification**:
    - All expected metrics present
    - Metrics have correct labels
    - No error metrics unexpected increase
    - Metrics endpoint responds quickly (< 100ms)
  - **Expected**: All greps succeed, metrics look correct
  - **Risk**: N/A

- [ ] **F4.5: FQDN Cache Initialization Verification**
  - **Setup**:
    ```bash
    # Create test config with FQDN client identifiers
    cat > fqdn-test-config.yml <<EOF
    upstream:
      default:
        - 8.8.8.8
    blocking:
      clientGroupsBlock:
        client1.example.com:
          - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
        client2.example.com:
          - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
        192.168.1.100:
          - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
    ports:
      dns: 53053
    log:
      level: debug
    EOF
    ```
  - **Command**:
    ```bash
    # Build and run with FQDN config
    make build
    ./bin/blocky serve -c fqdn-test-config.yml 2>&1 | tee blocky.log
    
    # Check logs
    grep "initializing FQDN IP cache" blocky.log
    grep "FQDN IP cache initialized" blocky.log
    
    # Verify no errors about ApplicationStarted
    grep "ApplicationStarted" blocky.log
    # Expected: No results
    ```
  - **Verification**:
    - FQDN cache initialization logs appear
    - Cache initialized with correct count (2 FQDNs in this test)
    - No errors or warnings about events
    - Blocking works correctly for FQDN clients
  - **Expected**: 
    - Log: "initializing FQDN IP cache"
    - Log: "FQDN IP cache initialized with 2 entries"
    - No ApplicationStarted errors
  - **Risk**: N/A

- [ ] **F4.6: End-to-End DNS Query Test**
  - **Command**:
    ```bash
    # Start blocky with default config
    make run &
    BLOCKY_PID=$!
    
    # Wait for startup
    sleep 3
    
    # Test DNS resolution
    dig @localhost -p 53 example.com
    dig @localhost -p 53 google.com
    dig @localhost -p 53 blocked-domain.com  # Should be blocked if in lists
    
    # Test blocking API
    curl -X POST http://localhost:4000/api/blocking/disable
    dig @localhost -p 53 blocked-domain.com  # Should NOT be blocked now
    
    curl -X POST http://localhost:4000/api/blocking/enable
    dig @localhost -p 53 blocked-domain.com  # Should be blocked again
    
    # Cleanup
    kill $BLOCKY_PID
    ```
  - **Verification**:
    - DNS queries resolve correctly
    - Blocking works when enabled
    - Blocking disabled via API works
    - No errors in logs
  - **Expected**: All DNS queries work, blocking behavior correct
  - **Risk**: N/A

- [ ] **F4.7: Documentation Verification**
  - **Files to Review**:
    - `CLAUDE.md` - Architecture updated
    - `resolver/resolver.go` - PostStarter documented
    - `resolver/blocking_resolver.go` - PostStart method documented
    - Code comments accurate throughout
  - **Verification**:
    - All new interfaces have godoc
    - Architecture changes reflected in CLAUDE.md
    - No outdated comments referencing event bus
  - **Expected**: Documentation complete and accurate
  - **Risk**: N/A

### Phase 4 Final Checklist

**All Must Pass:**
- [ ] ✅ Code review checklist 100% complete
- [ ] ✅ `make lint` - clean
- [ ] ✅ `make build` - succeeds
- [ ] ✅ `make test` - all pass
- [ ] ✅ `make e2e-test` - all pass
- [ ] ✅ Performance within 5% of baseline
- [ ] ✅ All Prometheus metrics emit correctly
- [ ] ✅ FQDN cache initializes correctly
- [ ] ✅ DNS queries work end-to-end
- [ ] ✅ Blocking enable/disable works
- [ ] ✅ Documentation complete and accurate
- [ ] ✅ No regressions found
- [ ] ✅ Zero event bus usage for lifecycle/metrics (Redis excluded)

---

## Risk Mitigation

### High-Risk Areas

#### 1. BlockingResolver FQDN Cache Initialization
**Risk**: DNS lookups might fail if upstream resolvers not ready

**Mitigation**:
- PostStart called AFTER DNS listeners up (correct timing)
- Add retry logic if DNS lookups fail (optional enhancement)
- Comprehensive logging for debugging
- Integration test verifies timing

**Rollback**: 
- Revert L1.2, L1.3, L1.4 commits
- Re-add ApplicationStarted event
- Restart server

#### 2. Metrics Might Break Silently
**Risk**: Prometheus metrics stop emitting but no errors shown

**Mitigation**:
- Integration test queries `/metrics` endpoint
- Manual verification step in F4.4
- Compare metrics before/after refactor
- Prometheus alerting (if configured) will detect missing metrics

**Rollback**:
- Revert M2.2, M2.3, M2.4 commits
- Restore metrics_event_publisher.go
- Restart server

#### 3. Event Bus Removal Breaks Redis Sync
**Risk**: Redis cross-instance sync stops working if event bus removed prematurely

**Mitigation**:
- E3.2 explicitly verifies Redis does NOT depend on event bus
- Redis uses Go channels (separate pattern)
- Keep evt package if Redis needs it
- Test Redis sync explicitly (if used)

**Rollback**:
- Restore evt package if accidentally deleted
- Check Redis subscriber code still works

### Moderate-Risk Areas

#### 4. Test Coverage Gaps
**Risk**: New code not adequately tested

**Mitigation**:
- L1.7 adds PostStart unit test
- L1.8 adds lifecycle integration test
- M2.7 adds metrics integration test
- F4.2 verifies coverage maintained

#### 5. Performance Regression
**Risk**: PostStart calls add latency to server startup

**Mitigation**:
- PostStart runs AFTER DNS listeners up (non-blocking for queries)
- F4.3 benchmarks performance
- FQDN cache init is async from DNS query path

---

## Rollback Strategy

### Per-Phase Rollback

**Phase 1 Rollback** (if lifecycle breaks):
```bash
# Revert Phase 1 commits
git log --oneline --grep="Phase 1\|Lifecycle\|PostStart" | head -10
git revert <commit-hash>...

# Or reset if not pushed
git reset --hard <commit-before-phase-1>

# Restore ApplicationStarted event
git checkout HEAD^ -- resolver/blocking_resolver.go cmd/serve.go evt/events.go

# Rebuild and test
make all
```

**Phase 2 Rollback** (if metrics break):
```bash
# Revert Phase 2 commits
git log --oneline --grep="Phase 2\|Metrics" | head -10
git revert <commit-hash>...

# Restore metrics_event_publisher.go
git checkout HEAD^ -- metrics/metrics_event_publisher.go evt/events.go

# Restore event publishes in resolvers
git checkout HEAD^ -- resolver/blocking_resolver.go resolver/caching_resolver.go

# Rebuild and test
make all

# Verify metrics endpoint
curl http://localhost:4000/metrics | grep blocky_
```

**Phase 3 Rollback** (if event bus deletion breaks something):
```bash
# Restore evt package
git checkout HEAD^ -- evt/

# Restore imports
git checkout HEAD^ -- <any-file-with-evt-import>

# Rebuild
make all
```

**Full Rollback** (nuclear option):
```bash
# Reset to before refactor started
git log --oneline | grep "Before metrics refactor"
git reset --hard <commit-hash>

# Or revert all commits in reverse order
git revert --no-commit <newest-commit>..<oldest-commit>
git commit -m "Revert metrics refactor"

# Verify old behavior works
make all
make e2e-test
```

---

## Success Criteria

### Technical Criteria
- [ ] ✅ PostStarter interface implemented and used
- [ ] ✅ BlockingResolver FQDN cache initializes via PostStart
- [ ] ✅ ApplicationStarted event completely removed
- [ ] ✅ All metrics events removed (8 events)
- [ ] ✅ metrics_event_publisher.go removed or empty
- [ ] ✅ All metrics use direct Prometheus emission
- [ ] ✅ Event bus package removed or documented as Redis-only
- [ ] ✅ Zero global state for lifecycle/metrics
- [ ] ✅ All tests pass (unit, integration, E2E)
- [ ] ✅ Lint clean
- [ ] ✅ Build succeeds
- [ ] ✅ Performance maintained (within 5%)
- [ ] ✅ Code coverage maintained or improved

### Behavioral Criteria
- [ ] ✅ DNS queries resolve correctly
- [ ] ✅ Blocking works (enable/disable via API)
- [ ] ✅ FQDN client identifiers work correctly
- [ ] ✅ Prometheus metrics emit correctly
- [ ] ✅ All existing functionality preserved
- [ ] ✅ No breaking changes to external APIs
- [ ] ✅ Configuration format unchanged

### Documentation Criteria
- [ ] ✅ PostStarter interface documented
- [ ] ✅ CLAUDE.md updated with new patterns
- [ ] ✅ Code comments accurate
- [ ] ✅ No outdated event bus references

---

## Timeline Estimate

**Phase 1 (Lifecycle)**: 1-2 days
- L1.1-L1.3: 2-3 hours
- L1.4-L1.6: 1 hour
- L1.7-L1.8: 2-3 hours
- Testing/verification: 2-3 hours

**Phase 2 (Metrics)**: 2-3 days
- M2.1: 1 hour (analysis)
- M2.2-M2.3: 3-4 hours (implementation)
- M2.4-M2.5: 1 hour (cleanup)
- M2.6-M2.7: 3-4 hours (testing)
- Verification: 2-3 hours

**Phase 3 (Cleanup)**: 1 day
- E3.1-E3.2: 2 hours (analysis)
- E3.3: 1 hour (deletion if safe)
- E3.4: 1 hour (documentation)
- Verification: 2 hours

**Phase 4 (Final Verification)**: 1 day
- All verification tasks: 6-8 hours

**Total Estimate**: 5-7 days

---

## Notes

### Implementation Order
1. **Must be sequential**: Phase 1 → Phase 2 → Phase 3 → Phase 4
2. **Within phases**: Most tasks are sequential, some analysis tasks parallelizable
3. **Testing**: Continuous throughout, final comprehensive verification in Phase 4

### Key Decision Points
- **After Phase 1**: Verify lifecycle works before touching metrics
- **After Phase 2**: Verify metrics still emit before deleting event bus
- **After Phase 3**: Final decision on evt package deletion

### Contingency Plans
- If Phase 1 fails: Rollback, investigate timing issues with PostStart
- If Phase 2 fails: Rollback metrics, keep event bus temporarily
- If Phase 3 fails: Keep evt package, document Redis dependency clearly

---

## Appendix: File Reference

### Files to Modify

**Phase 1:**
- `resolver/resolver.go` - Add PostStarter interface
- `resolver/blocking_resolver.go` - Implement PostStart, remove event subscription
- `server/server.go` - Call PostStart hooks in Start()
- `cmd/serve.go` - Remove ApplicationStarted publish
- `evt/events.go` - Remove ApplicationStarted constant
- `resolver/blocking_resolver_test.go` - Update tests
- `server/server_test.go` - Add lifecycle integration test

**Phase 2:**
- `resolver/blocking_resolver.go` - Add direct Prometheus metrics
- `resolver/caching_resolver.go` - Remove event publishes
- `metrics/metrics_event_publisher.go` - Remove or delete
- `evt/events.go` - Remove metrics event constants
- `metrics/metrics_test.go` - Update tests
- `metrics/integration_test.go` - Add integration test (new file)

**Phase 3:**
- `evt/` - Possibly delete directory
- `go.mod` - Remove EventBus dependency
- `CLAUDE.md` - Update documentation

### Key Code Locations

- **Resolver chain iteration**: `resolver/resolver.go:148` (ForEach function)
- **Server Start method**: `server/server.go:440-470`
- **BlockingResolver constructor**: `resolver/blocking_resolver.go:90-176`
- **FQDN cache init**: `resolver/blocking_resolver.go:625-634`
- **Event bus wrapper**: `evt/events.go`
- **Metrics registration**: `metrics/metrics.go:124`
- **Metrics event publisher**: `metrics/metrics_event_publisher.go`

### Grep Commands for Verification

```bash
# Find all event publishes
grep -r "evt.Bus().Publish" --include="*.go" | grep -v "_test.go"

# Find all event subscriptions
grep -r "evt.Bus().Subscribe" --include="*.go" | grep -v "_test.go"

# Find all PostStarter implementations
grep -r "func.*PostStart.*context.Context.*error" --include="*.go"

# Find all metrics events
grep -r "BlockingEnabled\|CachingResultCacheChanged" --include="*.go"

# Verify ApplicationStarted removed
grep -r "ApplicationStarted" --include="*.go"
# Expected: Zero results (except maybe comments)
```

---

**END OF WORK PLAN**
