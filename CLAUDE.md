# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Blocky is a DNS proxy and ad-blocker written in Go. It acts as a local DNS server that can block domains (ad-blocking, malware), cache responses, forward queries conditionally, and provide various DNS protocols (UDP/TCP, DoH, DoT).

**Key Features:**
- DNS blocking with external lists and regex support
- DNS caching and prefetching
- Conditional forwarding per client group
- Multiple protocol support (DNS, DoH, DoT)
- Query logging (CSV or database)
- Prometheus metrics
- REST API and CLI

## Build & Development Commands

### Building
```bash
make build              # Build binary to bin/blocky
make docker-build       # Build Docker image
```

### Testing
```bash
make test               # Run unit tests (excludes e2e)
make e2e-test           # Run end-to-end tests (requires Docker)
make race               # Run tests with race detector
```

Tests use Ginkgo/Gomega. To run specific tests:
```bash
go tool ginkgo -focus="pattern" ./path/to/package
```

### Linting & Formatting
```bash
make lint               # Run golangci-lint (auto-formats first)
make fmt                # Format code with gofumpt and goimports
```

### Running
```bash
make run                # Build and run with default config
./bin/blocky serve -c /path/to/config.yml   # Run with specific config
./bin/blocky --help     # View CLI commands
```

### Code Generation
```bash
make generate           # Run go generate (creates enums, API code)
```

## Architecture

### Resolver Chain Pattern

The core DNS resolution uses a **chain-of-responsibility pattern**. Each resolver in the chain processes a request and either:
1. Returns a response (short-circuits the chain)
2. Passes to the next resolver via `Next()`

Resolvers are composed at startup in `server/server.go` using `resolver.Chain()`. The order matters:

**Typical resolver chain order:**
1. **FQDNOnlyResolver** - Rejects non-FQDN queries
2. **SpecialUseDomainNamesResolver** - Handles special domains (.local, etc)
3. **FilteringResolver** - Filters by query type
4. **ClientNamesResolver** - Identifies client by IP/name
5. **MetricsResolver** - Records metrics
6. **QueryLoggingResolver** - Logs queries
7. **RewriterResolver** - Rewrites domains via regex
8. **HostsFileResolver** - Resolves from /etc/hosts
9. **CustomDNSResolver** - Custom domain mappings
10. **ConditionalUpstreamResolver** - Routes by domain pattern
11. **BlockingResolver** - Blocks based on lists
12. **CachingResolver** - Caches responses
13. **ECSResolver** - Adds EDNS Client Subnet
14. **EDEResolver** - Adds Extended DNS Errors
15. **UpstreamTreeResolver** - Final upstream resolution

### Key Components

**`resolver/`** - All DNS resolution logic (~20 resolver types)
- Each resolver is a `ChainedResolver` that implements `Resolve(ctx, req)`
- Base types: `typed` (for Type()), `configurable[T]` (for config), `NextResolver` (for chaining)

**`config/`** - Configuration parsing and types
- Loads YAML config, validates, applies defaults
- Each resolver has a corresponding config struct (e.g., `BlockingConfig`)

**`server/`** - DNS/HTTP server setup
- Creates DNS servers (UDP/TCP/DoH/DoT)
- Builds resolver chain based on config
- Exposes REST API endpoints

**`lists/`** - List downloader for blocking/allow lists
- Downloads and caches external lists
- Supports various formats (hosts, domains, etc)

**`cache/`** - Caching implementations
- In-memory and Redis cache support
- Used by `CachingResolver`

**`querylog/`** - Query logging backends
- CSV and database (MySQL/PostgreSQL) writers

**`cmd/`** - CLI commands (cobra-based)
- `serve` - Start DNS server
- `query` - Test DNS query
- `blocking` - Control blocking
- `lists` - Manage lists
- etc.

**`api/`** - OpenAPI generated API code
- Client and server stubs (generated via oapi-codegen)
- Actual handlers in `server/server_endpoints.go`

**`model/`** - Core types (Request, Response, etc)

**`util/`** - Utilities (TLS, DNS helpers, etc)

## Configuration

Config is YAML-based. See `config.yml` for an example. Key sections:
- `upstreams` - External DNS servers (supports groups, DoH, DoT)
- `blocking` - Block/allow lists per client group
- `caching` - Cache settings (TTL, prefetching)
- `queryLog` - Query logging (CSV or DB)
- `customDNS` - Custom domain-to-IP mappings
- `conditional` - Route specific domains to specific upstreams
- `ports` - Listening ports (DNS, HTTP, DoH, DoT)

## Testing Guidelines

- Tests use Ginkgo BDD style (`Describe`, `It`, `BeforeEach`)
- Use Gomega matchers (`Expect().Should()`, `Eventually()`)
- Use always Ginkgo with Gomega.
- Test files: `*_test.go`, suite files: `*_suite_test.go`
- Mock external dependencies (DNS servers, HTTP, Redis, DB)
- E2E tests use testcontainers for Docker-based integration tests
- Dont create tests for generated enums
- Always use "dig" with local running blocky `make run` to perform manual tests. Put testconfig into "config.yml"

## General notes
- always execute "make lint" after code changes and fix lint errors
- always execute "make all" after code changes and fix all errors
- if working with specification implementation with check lists, mark them as finished after implementation

## Code Generation

The project uses several code generators:
- **go-enum** - Enum types with String() methods (see `//go:generate` in config files). Generate all enums with this approach.
- **oapi-codegen** - OpenAPI client/server from `api/*.cfg.yaml`
- **ginkgo** - Test suite generation

Generated files are marked with `// Code generated ... DO NOT EDIT`

## Development Notes

- **Go version**: 1.25+ (see go.mod)
- **Linter**: golangci-lint v2.2.1 with strict rules (see .golangci.yml)
- **Logging**: logrus with prefixed formatter
- **DNS library**: github.com/miekg/dns
- **HTTP router**: go-chi/chi/v5
- **Metrics**: Prometheus (github.com/prometheus/client_golang)

## Documentation Guidelines
- we use mkdocs as documentation generator
- documentation is located in docs/
- docs/config.yml contains a full configuration example with all fields and comments (filed mandatory/optional, default val etc)
- after changes, check if the documentation is still valid or needs to be updated
- we don't add extra file per feature. All new features will be documented in existing files (see docs)
- new configuration is documented in docs/config.yml

### Common Patterns

**Adding a new resolver:**
1. Create `resolver/my_resolver.go`
2. Embed `typed`, `configurable[MyConfig]`, `NextResolver`
3. Implement `Resolve(ctx context.Context, req *model.Request) (*model.Response, error)`
4. Add constructor `NewMyResolver(cfg *config.MyConfig) *MyResolver`
5. Wire into chain in `server/server.go`
6. Add config struct in `config/my.go`

**Adding a CLI command:**
1. Create command in `cmd/mycommand.go`
2. Add to `NewRootCommand()` in `cmd/root.go`
3. Use cobra patterns (see existing commands)

## API

REST API runs on port 4000 by default (configurable via `ports.http`).

Key endpoints:
- `GET /api/blocking/status` - Blocking status
- `POST /api/blocking/enable` - Enable blocking
- `POST /api/blocking/disable` - Disable blocking
- `POST /api/lists/refresh` - Refresh lists
- `GET /api/query?query=domain.com` - Test query
- `GET /metrics` - Prometheus metrics

CLI can interact with API:
```bash
./blocky blocking enable
./blocky query example.com
./blocky lists refresh
```
