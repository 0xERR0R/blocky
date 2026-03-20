# E2E Test Expansion & Framework Refactoring

## Overview

Expand e2e test coverage for untested features and refactor the test framework for improved readability and reduced boilerplate. Tests use Ginkgo/Gomega BDD style with testcontainers (black-box approach).

## Phase 1: New E2E Tests

All new tests follow existing patterns: Ginkgo/Gomega, testcontainers, `doDNSRequest`/`BeDNSRecord` matchers, `DeferCleanup`. Each feature gets its own test file.

### `ecs_test.go` — EDNS Client Subnet

Note: Sending queries with ECS options requires manual EDNS0 CLIENT-SUBNET construction on `dns.Msg` — no existing helper covers this. Create a local helper (e.g., `addECSOption(msg, ip, mask)`) for these tests.

**ECS as client identifier:**
- Configure `ecs.useAsClient: true` with netmask /32
- Configure `clientGroupsBlock` mapping the ECS subnet to a blocking group with a denylist
- Send DNS query with ECS option containing a specific IP
- Verify blocking rules apply based on ECS subnet, not actual source IP

**ECS forwarding:**
- Configure `ecs.forward: true`
- Send query with ECS option
- Verify the ECS option is preserved in the response back to the client (response-side verification)
- Note: Verifying what mokka receives on the request side is not feasible with the current mokka image. If deeper verification is needed, this can be revisited when mokka gains inspection capabilities.

**ECS with IPv4/IPv6 masks:**
- Configure custom `ecsIpv4Mask` and `ecsIpv6Mask` values
- Send query with ECS option with a /32 mask
- Verify the response ECS option reflects the configured mask size (truncated appropriately)

### `fqdn_only_test.go` — FQDN-Only Mode

**Non-FQDN rejected:**
- Enable `fqdnOnly: true` in config
- Query bare hostname `myserver` (no dots)
- Expect REFUSED response code

**FQDN accepted:**
- Same config with `fqdnOnly: true`
- Query `myserver.example.com.` (fully qualified)
- Expect normal resolution via upstream

**Disabled mode:**
- Default config without `fqdnOnly` (or `fqdnOnly: false`)
- Query bare hostname → resolves normally via upstream

### `filtering_test.go` — Query Type Filtering

**AAAA filtering:**
- Configure `filtering.queryTypes: [AAAA]`
- Query domain with type AAAA → expect empty response with NOERROR
- Query same domain with type A → resolves normally

**Multiple type filtering:**
- Configure `filtering.queryTypes: [AAAA, MX]`
- Query AAAA → filtered
- Query MX → filtered
- Query A → resolves normally

**No filtering passthrough:**
- No filtering config
- All query types resolve normally

### `hosts_file_test.go` — Hosts File Resolver

**Local mounted file:**
- Create a hosts file with entries like `192.168.1.1 myhost.example`
- Mount it into the blocky container
- Configure `hostsFile` to use the mounted path
- Query `myhost.example` → resolves to `192.168.1.1`

Note: Hosts file tests use `.example` TLD (not `.local`) to avoid conflict with the SUDN resolver, which intercepts `.local` queries (RFC 6762) before the hosts file resolver in the chain.

**HTTP-served file:**
- Serve a hosts file via `staticServerImage` (consistent with blocklist pattern)
- Configure `hostsFile` source as HTTP URL
- Query domain from hosts file → resolves correctly

**Custom TTL:**
- Configure `hostsFile.hostsTTL: 5m`
- Query hosts file entry → verify TTL matches configured value

**Loopback filtering:**
- Hosts file contains entries pointing to `127.0.0.1`
- Configure `hostsFile.filterLoopback: true`
- Query loopback entry → not resolved (falls through to upstream or NXDOMAIN)
- Query non-loopback entry → resolves normally

**Subdomain resolution:**
- Hosts file contains `192.168.1.1 myhost.example`
- Query `sub.myhost.example` → resolves to `192.168.1.1` (automatic subdomain support)

### `sudn_test.go` — Special Use Domain Names

**RFC 6761 reserved domains:**
- Default SUDN config (enabled)
- Query `something.localhost` → handled locally, not forwarded upstream
- Query `something.invalid` → NXDOMAIN
- Query PTR for private range (e.g., `1.0.168.192.in-addr.arpa`) → handled locally

**RFC 6762 mDNS:**
- Query `mydevice.local` → blocked/handled (not forwarded)

**RFC 6762 Appendix G TLDs:**
- Enable RFC 6762 Appendix G in config
- Query `.lan`, `.internal`, `.home`, `.corp` domains → blocked
- Verify each returns appropriate response

**SUDN disabled:**
- Configure `specialUseDomains.rfc6762-appendixG: false` (and potentially disable other SUDN)
- Queries that were previously blocked now forward to upstream
- Verify upstream receives the query

**Partial config:**
- Enable base SUDN but disable RFC 6762 Appendix G
- RFC 6761 domains still handled locally
- Appendix G TLDs (`.lan`, `.home`, etc.) forwarded to upstream

### `api_test.go` — Additional API Endpoints

**Cache flush:**
- Configure caching with upstream (mokka)
- Make a DNS query → response is cached
- Call `POST /api/cache/flush` via HTTP
- Repeat same query → must hit upstream again (verify via response change or mokka counter)

**Query endpoint:**
- Call `POST /api/query` with JSON body containing domain and query type (see OpenAPI spec at `docs/api/openapi.yaml` for request/response schema)
- Verify JSON response contains expected answer records
- Test with both existing and non-existing domains

**Blocking disable with duration:**
- Configure blocking with a denylist
- Verify domain is blocked
- Call `/api/blocking/disable` with `duration=3s` parameter
- Verify domain is unblocked
- Wait for duration to expire
- Verify domain is blocked again

**Blocking disable with groups:**
- Configure blocking with two groups (e.g., `ads` and `malware`)
- Verify domains from both groups are blocked
- Call `/api/blocking/disable` with `groups=ads` parameter
- Verify `ads` group domain is unblocked
- Verify `malware` group domain is still blocked
- Re-enable via `/api/blocking/enable`

## Phase 2: Test Framework Refactoring

Performed after all Phase 1 tests are green and passing. Existing tests serve as the safety net.

### 2.1 Config Readability — `dedent()` Helper

**Problem:** Config is passed as `[]string` of individual YAML lines with manual indentation. Hard to read as YAML.

**Solution:** Introduce a `dedent(s string) string` function that strips common leading whitespace. Change `createBlockyContainer` to accept a single YAML string instead of `[]string`.

**Before:**
```go
createBlockyContainer(ctx, e2eNet,
    "upstreams:",
    "  groups:",
    "    default:",
    "      - moka",
    "blocking:",
    "  denylists:",
    "    ads:",
    "      - "+listURL,
    "  blockType: zeroIp",
)
```

Note: Mokka containers are referenced by their Docker network alias (e.g., `"moka"`) directly in the YAML config. No host/port interpolation is needed for the common case.

**After:**
```go
createBlockyContainer(ctx, e2eNet, dedent(`
    upstreams:
      groups:
        default:
          - moka
    blocking:
      denylists:
        ads:
          - `+listURL+`
      blockType: zeroIp
`))
```

Raw YAML remains visible and editable. No DSL, no abstraction layer — just cleaner formatting.

### 2.2 Container Setup Helpers

**Problem:** Each test repeats 10-15 lines of container setup (network + mokka + blocky).

**Solution:** Extract common topologies into helper functions:

```go
// mokkaSpec defines a mock DNS upstream with its network alias and rules
type mokkaSpec struct {
    alias string   // Docker network alias, used directly in YAML config (e.g., "moka1")
    rules []string // mokka query rules (e.g., `A google/NOERROR("A 1.2.3.4 123")`)
}

type testEnv struct {
    network *testcontainers.DockerNetwork
    mokkas  map[string]testcontainers.Container // keyed by alias
    blocky  testcontainers.Container
    httpSrv testcontainers.Container            // nil if no HTTP server
}

func setupBlockyWithMokka(ctx context.Context, mokkas []mokkaSpec, config string) *testEnv
func setupBlockyWithHTTPAndMokka(ctx context.Context, mokkas []mokkaSpec, files map[string]string, config string) *testEnv
```

Usage example with multiple upstreams:
```go
env := setupBlockyWithMokka(ctx, []mokkaSpec{
    {alias: "moka1", rules: []string{`A google/NOERROR("A 1.2.3.4 123")`}},
    {alias: "moka2", rules: []string{`A internal/NOERROR("A 10.0.0.1 300")`}},
}, dedent(`
    upstreams:
      groups:
        default:
          - moka1
        internal:
          - moka2
`))
```

- `setupBlockyWithMokka` — creates network + one or more mokka containers + blocky. Each mokka's network alias is used directly in the YAML config string — no interpolation needed.
- `setupBlockyWithHTTPAndMokka` — same but also creates an HTTP static file server. The HTTP server container is accessible via `env.httpSrv`.
- Both call `DeferCleanup` internally.
- Individual container creation functions remain available for non-standard setups.

### 2.3 Assertion Helpers

**Problem:** DNS request + assertion chains are verbose and repetitive.

**Solution:** Higher-level assertion functions with variadic optional matchers:

```go
// Basic resolution check
func expectResolve(ctx context.Context, blocky testcontainers.Container,
    domain string, qType dns.Type, expected string, extra ...types.GomegaMatcher)

// NXDOMAIN response
func expectNXDomain(ctx context.Context, blocky testcontainers.Container,
    domain string, qType dns.Type)

// Empty response with NOERROR
func expectNoAnswer(ctx context.Context, blocky testcontainers.Container,
    domain string, qType dns.Type)

// REFUSED response
func expectRefused(ctx context.Context, blocky testcontainers.Container,
    domain string, qType dns.Type)

// Async resolution (for prefetch, delayed startup, etc.)
func expectEventually(ctx context.Context, blocky testcontainers.Container,
    domain string, qType dns.Type, expected string, timeout time.Duration, extra ...types.GomegaMatcher)
```

**Examples:**
```go
// Simple
expectResolve(ctx, blocky, "google.com.", A, "1.2.3.4")

// With TTL check
expectResolve(ctx, blocky, "google.com.", A, "1.2.3.4", HaveTTL(BeNumerically("==", 300)))

// Blocked
expectNXDomain(ctx, blocky, "blocked.com.", A)

// Filtered query type
expectNoAnswer(ctx, blocky, "example.com.", AAAA)

// FQDN-only rejection
expectRefused(ctx, blocky, "barehost", A)

// Prefetch/async
expectEventually(ctx, blocky, "cached.com.", A, "1.2.3.4", "5s",
    HaveTTL(BeNumerically(">", 0)))
```

Raw `doDNSRequest` + manual matchers remain available for complex/unusual assertions.

### 2.4 Migration Strategy

1. Add all new helpers to `helper.go` (or a new `assert_helpers.go`)
2. Migrate existing test files one at a time, alphabetically
3. Run `make e2e-test` after each file migration
4. One commit per migrated file for easy bisecting
5. No behavior changes — purely mechanical transformation

## Execution Order

1. **Phase 1:** Write new test files using the current `...string` variadic API for `createBlockyContainer` and existing assertion patterns (`ecs_test.go`, `fqdn_only_test.go`, `filtering_test.go`, `hosts_file_test.go`, `sudn_test.go`, `api_test.go`)
2. **Phase 2a:** Add `dedent()`, assertion helpers, container setup helpers. Change `createBlockyContainer` signature to accept a single YAML string.
3. **Phase 2b:** Migrate new tests to use helpers
4. **Phase 2c:** Migrate existing tests to use helpers (one file per commit)

## Test Execution

All tests run via `make e2e-test`. No changes to the test execution pipeline.
