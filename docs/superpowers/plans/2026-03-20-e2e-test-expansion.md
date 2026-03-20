# E2E Test Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 6 new e2e test files covering untested features (ECS, FQDN-only, query type filtering, hosts file, SUDN, API endpoints), then refactor the test framework for readability.

**Architecture:** Phase 1 writes new tests using the existing `...string` variadic API for `createBlockyContainer` and current assertion patterns. Phase 2 introduces helpers (`dedent()`, assertion shortcuts, container setup builders) and migrates all tests to use them.

**Tech Stack:** Go, Ginkgo/Gomega BDD, testcontainers-go, miekg/dns

**Spec:** `docs/superpowers/specs/2026-03-20-e2e-test-expansion-design.md`

---

## Phase 1: New E2E Tests

### Task 1: `fqdn_only_test.go` — FQDN-Only Mode

The simplest new test file. Tests that blocky rejects bare hostnames when `fqdnOnly` is enabled.

**Files:**
- Create: `e2e/fqdn_only_test.go`

**Config reference:** `fqdnOnly` uses the `toEnable` struct (`config/config.go:339`), YAML key is `fqdnOnly.enable`.

- [ ] **Step 1: Create `fqdn_only_test.go` with all test cases**

```go
package e2e

import (
	"context"

	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

var _ = Describe("FQDN only mode", func() {
	var (
		e2eNet *testcontainers.DockerNetwork
		blocky testcontainers.Container
		err    error
	)

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)

		_, err = createDNSMokkaContainer(ctx, "moka", e2eNet,
			`A example.com/NOERROR("A 1.2.3.4 123")`,
			`A myserver/NOERROR("A 5.6.7.8 300")`,
		)
		Expect(err).Should(Succeed())
	})

	When("fqdnOnly is enabled", func() {
		BeforeEach(func(ctx context.Context) {
			blocky, err = createBlockyContainer(ctx, e2eNet,
				"upstreams:",
				"  groups:",
				"    default:",
				"      - moka",
				"fqdnOnly:",
				"  enable: true",
			)
			Expect(err).Should(Succeed())
		})

		It("should reject non-FQDN queries with REFUSED", func(ctx context.Context) {
			msg := util.NewMsgWithQuestion("myserver.", A)
			resp, err := doDNSRequest(ctx, blocky, msg)
			Expect(err).Should(Succeed())
			Expect(resp.Rcode).Should(Equal(dns.RcodeRefused))
		})

		It("should resolve FQDN queries normally", func(ctx context.Context) {
			msg := util.NewMsgWithQuestion("example.com.", A)
			Expect(doDNSRequest(ctx, blocky, msg)).
				Should(
					SatisfyAll(
						BeDNSRecord("example.com.", A, "1.2.3.4"),
						HaveTTL(BeNumerically("==", 123)),
					))
		})
	})

	When("fqdnOnly is disabled (default)", func() {
		BeforeEach(func(ctx context.Context) {
			blocky, err = createBlockyContainer(ctx, e2eNet,
				"upstreams:",
				"  groups:",
				"    default:",
				"      - moka",
			)
			Expect(err).Should(Succeed())
		})

		It("should resolve non-FQDN queries normally", func(ctx context.Context) {
			msg := util.NewMsgWithQuestion("myserver.", A)
			Expect(doDNSRequest(ctx, blocky, msg)).
				Should(
					SatisfyAll(
						BeDNSRecord("myserver.", A, "5.6.7.8"),
						HaveTTL(BeNumerically("==", 300)),
					))
		})
	})
})
```

- [ ] **Step 2: Run e2e tests to verify**

Run: `make e2e-test` (or `go test -v -count=1 -tags e2e -run "FQDN" ./e2e/...` for targeted run)
Expected: All 3 tests pass.

- [ ] **Step 3: Commit**

```bash
git add e2e/fqdn_only_test.go
git commit -m "test(e2e): add FQDN-only mode tests"
```

---

### Task 2: `filtering_test.go` — Query Type Filtering

Tests that blocky filters specified DNS query types (e.g., AAAA, MX).

**Files:**
- Create: `e2e/filtering_test.go`

**Config reference:** `Filtering.QueryTypes` is a `QTypeSet` (`config/filtering.go`), YAML key is `filtering.queryTypes`.

- [ ] **Step 1: Create `filtering_test.go` with all test cases**

```go
package e2e

import (
	"context"

	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

var _ = Describe("Query type filtering", func() {
	var (
		e2eNet *testcontainers.DockerNetwork
		blocky testcontainers.Container
		err    error
	)

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)

		_, err = createDNSMokkaContainer(ctx, "moka", e2eNet,
			`A example.com/NOERROR("A 1.2.3.4 123")`,
			`AAAA example.com/NOERROR("AAAA 2001:db8::1 123")`,
			`MX example.com/NOERROR("MX 10 mail.example.com. 123")`,
		)
		Expect(err).Should(Succeed())
	})

	When("AAAA filtering is configured", func() {
		BeforeEach(func(ctx context.Context) {
			blocky, err = createBlockyContainer(ctx, e2eNet,
				"upstreams:",
				"  groups:",
				"    default:",
				"      - moka",
				"filtering:",
				"  queryTypes:",
				"    - AAAA",
			)
			Expect(err).Should(Succeed())
		})

		It("should filter AAAA queries and return empty response", func(ctx context.Context) {
			msg := util.NewMsgWithQuestion("example.com.", AAAA)
			resp, err := doDNSRequest(ctx, blocky, msg)
			Expect(err).Should(Succeed())
			Expect(resp.Rcode).Should(Equal(dns.RcodeSuccess))
			Expect(resp.Answer).Should(BeEmpty())
		})

		It("should pass through A queries normally", func(ctx context.Context) {
			msg := util.NewMsgWithQuestion("example.com.", A)
			Expect(doDNSRequest(ctx, blocky, msg)).
				Should(
					SatisfyAll(
						BeDNSRecord("example.com.", A, "1.2.3.4"),
						HaveTTL(BeNumerically("==", 123)),
					))
		})
	})

	When("multiple query types are filtered", func() {
		BeforeEach(func(ctx context.Context) {
			blocky, err = createBlockyContainer(ctx, e2eNet,
				"upstreams:",
				"  groups:",
				"    default:",
				"      - moka",
				"filtering:",
				"  queryTypes:",
				"    - AAAA",
				"    - MX",
			)
			Expect(err).Should(Succeed())
		})

		It("should filter all configured query types", func(ctx context.Context) {
			By("filtering AAAA queries", func() {
				msg := util.NewMsgWithQuestion("example.com.", AAAA)
				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())
				Expect(resp.Answer).Should(BeEmpty())
			})

			By("filtering MX queries", func() {
				msg := util.NewMsgWithQuestion("example.com.", MX)
				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())
				Expect(resp.Answer).Should(BeEmpty())
			})

			By("passing through A queries", func() {
				msg := util.NewMsgWithQuestion("example.com.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(BeDNSRecord("example.com.", A, "1.2.3.4"))
			})
		})
	})

	When("no filtering is configured", func() {
		BeforeEach(func(ctx context.Context) {
			blocky, err = createBlockyContainer(ctx, e2eNet,
				"upstreams:",
				"  groups:",
				"    default:",
				"      - moka",
			)
			Expect(err).Should(Succeed())
		})

		It("should pass through all query types", func(ctx context.Context) {
			By("resolving A queries", func() {
				msg := util.NewMsgWithQuestion("example.com.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(BeDNSRecord("example.com.", A, "1.2.3.4"))
			})

			By("resolving AAAA queries", func() {
				msg := util.NewMsgWithQuestion("example.com.", AAAA)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(BeDNSRecord("example.com.", AAAA, "2001:db8::1"))
			})
		})
	})
})
```

- [ ] **Step 2: Run e2e tests to verify**

Run: `make e2e-test` (or targeted: `go test -v -count=1 -tags e2e -run "Query type" ./e2e/...`)
Expected: All tests pass.

- [ ] **Step 3: Commit**

```bash
git add e2e/filtering_test.go
git commit -m "test(e2e): add query type filtering tests"
```

---

### Task 3: `hosts_file_test.go` — Hosts File Resolver

Tests hosts file resolution with both local mounted files and HTTP-served files.

**Files:**
- Create: `e2e/hosts_file_test.go`

**Config reference:** `HostsFile` struct (`config/hosts_file.go`), YAML keys: `hostsFile.sources`, `hostsFile.hostsTTL`, `hostsFile.filterLoopback`. Sources accept file paths and HTTP URLs.

**Important:** Use `.example` TLD (not `.local`) to avoid SUDN resolver intercepting `.local` queries.

- [ ] **Step 1: Create `hosts_file_test.go` with all test cases**

```go
package e2e

import (
	"context"

	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

var _ = Describe("Hosts file resolver", func() {
	var (
		e2eNet *testcontainers.DockerNetwork
		blocky testcontainers.Container
		err    error
	)

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)

		// Fallback upstream for queries not in hosts file
		_, err = createDNSMokkaContainer(ctx, "moka", e2eNet,
			`A fallback.example/NOERROR("A 9.9.9.9 300")`,
		)
		Expect(err).Should(Succeed())
	})

	Describe("Local mounted hosts file", func() {
		When("a hosts file is mounted into the container", func() {
			BeforeEach(func(ctx context.Context) {
				// Create a local temp file and mount it into the blocky container
				// by using buildBlockyContainerRequest and adding an extra ContainerFile
				hostsFile := createTempFile(
					"192.168.1.1 myhost.example",
					"10.0.0.1 server.example",
				)

				confFile := createTempFile(
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
					"hostsFile:",
					"  sources:",
					"    - /app/hosts.txt",
					"  hostsTTL: 5m",
				)

				cfg, cfgErr := config.LoadConfig(confFile, true)
				Expect(cfgErr).Should(Succeed())

				req := buildBlockyContainerRequest(confFile)
				// Mount the hosts file into the container
				req.Files = append(req.Files, testcontainers.ContainerFile{
					HostFilePath:      hostsFile,
					ContainerFilePath: "/app/hosts.txt",
					FileMode:          700,
				})

				ctx, cancel := context.WithTimeout(ctx, 2*startupTimeout)
				defer cancel()

				var startErr error
				blocky, startErr = startContainerWithNetwork(ctx, req, "blocky", e2eNet)
				Expect(startErr).Should(Succeed())
				Expect(checkBlockyReadiness(ctx, cfg, blocky)).Should(Succeed())
			})

			It("should resolve domains from the hosts file", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("myhost.example.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(
						SatisfyAll(
							BeDNSRecord("myhost.example.", A, "192.168.1.1"),
							HaveTTL(BeNumerically("==", 300)), // 5m = 300s
						))
			})

			It("should resolve multiple hosts from the file", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("server.example.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(
						SatisfyAll(
							BeDNSRecord("server.example.", A, "10.0.0.1"),
							HaveTTL(BeNumerically("==", 300)),
						))
			})
		})
	})

	Describe("HTTP-served hosts file", func() {
		When("hosts file is served via HTTP", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createHTTPServerContainer(ctx, "httpserver", e2eNet, "hosts.txt",
					"172.16.0.1 webserver.example",
				)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
					"hostsFile:",
					"  sources:",
					"    - http://httpserver:8080/hosts.txt",
				)
				Expect(err).Should(Succeed())
			})

			It("should resolve domains from the HTTP-served hosts file", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("webserver.example.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(BeDNSRecord("webserver.example.", A, "172.16.0.1"))
			})
		})
	})

	Describe("Custom TTL", func() {
		When("hostsTTL is configured", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createHTTPServerContainer(ctx, "httpserver", e2eNet, "hosts.txt",
					"192.168.1.1 myhost.example",
				)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
					"hostsFile:",
					"  sources:",
					"    - http://httpserver:8080/hosts.txt",
					"  hostsTTL: 2m",
				)
				Expect(err).Should(Succeed())
			})

			It("should use the configured TTL for hosts file responses", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("myhost.example.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(
						SatisfyAll(
							BeDNSRecord("myhost.example.", A, "192.168.1.1"),
							HaveTTL(BeNumerically("==", 120)), // 2m = 120s
						))
			})
		})
	})

	Describe("Loopback filtering", func() {
		When("filterLoopback is enabled", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createHTTPServerContainer(ctx, "httpserver", e2eNet, "hosts.txt",
					"127.0.0.1 loopback.example",
					"192.168.1.1 normal.example",
				)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
					"hostsFile:",
					"  sources:",
					"    - http://httpserver:8080/hosts.txt",
					"  filterLoopback: true",
				)
				Expect(err).Should(Succeed())
			})

			It("should not resolve loopback entries", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("loopback.example.", A)
				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())
				// Loopback entry filtered out, falls through to upstream which returns NXDOMAIN or SERVFAIL
				Expect(resp.Answer).Should(BeEmpty())
			})

			It("should resolve non-loopback entries normally", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("normal.example.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(BeDNSRecord("normal.example.", A, "192.168.1.1"))
			})
		})
	})

	Describe("Subdomain resolution", func() {
		When("a hosts file entry exists", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createHTTPServerContainer(ctx, "httpserver", e2eNet, "hosts.txt",
					"192.168.1.1 myhost.example",
				)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
					"hostsFile:",
					"  sources:",
					"    - http://httpserver:8080/hosts.txt",
				)
				Expect(err).Should(Succeed())
			})

			It("should also resolve subdomains of hosts file entries", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("sub.myhost.example.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(BeDNSRecord("sub.myhost.example.", A, "192.168.1.1"))
			})
		})
	})
})
```

- [ ] **Step 2: Run e2e tests to verify**

Run: `make e2e-test` (or targeted: `go test -v -count=1 -tags e2e -run "Hosts file" ./e2e/...`)
Expected: All tests pass.

- [ ] **Step 3: Commit**

```bash
git add e2e/hosts_file_test.go
git commit -m "test(e2e): add hosts file resolver tests"
```

---

### Task 4: `sudn_test.go` — Special Use Domain Names

Comprehensive SUDN tests covering RFC 6761, RFC 6762, Appendix G, disabled, and partial configs.

**Files:**
- Create: `e2e/sudn_test.go`

**Config reference:** `SUDN` struct (`config/sudn.go`), YAML keys: `specialUseDomains.enable` (default: true), `specialUseDomains.rfc6762-appendixG` (default: true). The SUDN resolver (`resolver/sudn_resolver.go`) returns NXDOMAIN for `.invalid`, handles `.localhost` locally, blocks `.local` (RFC 6762), and blocks `.lan`/`.internal`/`.home`/`.corp` (Appendix G).

- [ ] **Step 1: Create `sudn_test.go` with all test cases**

```go
package e2e

import (
	"context"

	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

var _ = Describe("Special Use Domain Names (SUDN)", func() {
	var (
		e2eNet *testcontainers.DockerNetwork
		blocky testcontainers.Container
		err    error
	)

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)

		// Upstream that responds to everything - used to verify queries are NOT forwarded
		_, err = createDNSMokkaContainer(ctx, "moka", e2eNet,
			`A something.localhost/NOERROR("A 1.2.3.4 300")`,
			`A something.invalid/NOERROR("A 1.2.3.4 300")`,
			`A mydevice.local/NOERROR("A 1.2.3.4 300")`,
			`A myhost.lan/NOERROR("A 1.2.3.4 300")`,
			`A myhost.internal/NOERROR("A 1.2.3.4 300")`,
			`A myhost.home/NOERROR("A 1.2.3.4 300")`,
			`A myhost.corp/NOERROR("A 1.2.3.4 300")`,
			`A google.com/NOERROR("A 8.8.8.8 300")`,
		)
		Expect(err).Should(Succeed())
	})

	Describe("RFC 6761 reserved domains", func() {
		When("SUDN is enabled (default)", func() {
			BeforeEach(func(ctx context.Context) {
				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
				)
				Expect(err).Should(Succeed())
			})

			It("should handle .localhost locally and return loopback", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("something.localhost.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(BeDNSRecord("something.localhost.", A, "127.0.0.1"))
			})

			It("should return NXDOMAIN for .invalid", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("something.invalid.", A)
				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())
				Expect(resp.Rcode).Should(Equal(dns.RcodeNameError))
			})

			It("should handle PTR for private ranges locally", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("1.0.168.192.in-addr.arpa.", dns.Type(dns.TypePTR))
				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())
				// Should be handled locally (not forwarded), likely NXDOMAIN since no PTR is configured
				Expect(resp.Rcode).ShouldNot(Equal(dns.RcodeServerFailure))
			})
		})
	})

	Describe("RFC 6762 mDNS", func() {
		When("SUDN is enabled (default)", func() {
			BeforeEach(func(ctx context.Context) {
				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
				)
				Expect(err).Should(Succeed())
			})

			It("should block .local domains (not forward to upstream)", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("mydevice.local.", A)
				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())
				// .local is handled by SUDN - should NOT return upstream's 1.2.3.4
				Expect(resp.Answer).ShouldNot(ContainElement(BeDNSRecord("mydevice.local.", A, "1.2.3.4")))
			})
		})
	})

	Describe("RFC 6762 Appendix G TLDs", func() {
		When("rfc6762-appendixG is enabled (default)", func() {
			BeforeEach(func(ctx context.Context) {
				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
				)
				Expect(err).Should(Succeed())
			})

			It("should block .lan domains", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("myhost.lan.", A)
				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())
				Expect(resp.Rcode).Should(Equal(dns.RcodeNameError))
			})

			It("should block .internal domains", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("myhost.internal.", A)
				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())
				Expect(resp.Rcode).Should(Equal(dns.RcodeNameError))
			})

			It("should block .home domains", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("myhost.home.", A)
				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())
				Expect(resp.Rcode).Should(Equal(dns.RcodeNameError))
			})

			It("should block .corp domains", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("myhost.corp.", A)
				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())
				Expect(resp.Rcode).Should(Equal(dns.RcodeNameError))
			})

			It("should still resolve normal domains via upstream", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("google.com.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(BeDNSRecord("google.com.", A, "8.8.8.8"))
			})
		})
	})

	Describe("SUDN disabled", func() {
		When("SUDN is completely disabled", func() {
			BeforeEach(func(ctx context.Context) {
				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
					"specialUseDomains:",
					"  enable: false",
				)
				Expect(err).Should(Succeed())
			})

			It("should forward .invalid to upstream", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("something.invalid.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(BeDNSRecord("something.invalid.", A, "1.2.3.4"))
			})

			It("should forward .lan to upstream", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("myhost.lan.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(BeDNSRecord("myhost.lan.", A, "1.2.3.4"))
			})
		})
	})

	Describe("Partial config", func() {
		When("base SUDN enabled but Appendix G disabled", func() {
			BeforeEach(func(ctx context.Context) {
				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
					"specialUseDomains:",
					"  rfc6762-appendixG: false",
				)
				Expect(err).Should(Succeed())
			})

			It("should still handle RFC 6761 domains locally", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("something.invalid.", A)
				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())
				Expect(resp.Rcode).Should(Equal(dns.RcodeNameError))
			})

			It("should forward Appendix G TLDs to upstream", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("myhost.lan.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(BeDNSRecord("myhost.lan.", A, "1.2.3.4"))
			})

			It("should forward .home to upstream", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("myhost.home.", A)
				Expect(doDNSRequest(ctx, blocky, msg)).
					Should(BeDNSRecord("myhost.home.", A, "1.2.3.4"))
			})
		})
	})
})
```

- [ ] **Step 2: Run e2e tests to verify**

Run: `make e2e-test` (or targeted: `go test -v -count=1 -tags e2e -run "Special Use" ./e2e/...`)
Expected: All tests pass.

- [ ] **Step 3: Commit**

```bash
git add e2e/sudn_test.go
git commit -m "test(e2e): add comprehensive SUDN tests"
```

---

### Task 5: `api_test.go` — Additional API Endpoints

Tests cache flush, query endpoint, blocking disable with duration, and blocking disable with groups.

**Files:**
- Create: `e2e/api_test.go`

**API reference (from `docs/api/openapi.yaml`):**
- `POST /api/cache/flush` — clears DNS cache
- `POST /api/query` — request body: `{"query": "domain.com", "type": "A"}`, response: `{"reason": "...", "response": "...", "responseType": "..."}`
- `GET /api/blocking/disable?duration=3s` — disable blocking for duration
- `GET /api/blocking/disable?groups=ads` — disable specific groups

- [ ] **Step 1: Create `api_test.go` with all test cases**

```go
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"time"

	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

var _ = Describe("API endpoints", func() {
	var (
		e2eNet *testcontainers.DockerNetwork
		blocky testcontainers.Container
		err    error
	)

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)
	})

	Describe("Cache flush", func() {
		When("caching is enabled", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createDNSMokkaContainer(ctx, "moka", e2eNet,
					`A cached.example.com/NOERROR("A 1.2.3.4 300")`,
				)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
					"ports:",
					"  http: 4000",
					"caching:",
					"  minTime: 5m",
				)
				Expect(err).Should(Succeed())
			})

			It("should clear cache via API", func(ctx context.Context) {
				host, port, err := getContainerHostPort(ctx, blocky, "4000/tcp")
				Expect(err).Should(Succeed())
				baseURL := "http://" + net.JoinHostPort(host, port)

				By("populating cache with a query", func() {
					msg := util.NewMsgWithQuestion("cached.example.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(BeDNSRecord("cached.example.com.", A, "1.2.3.4"))
				})

				By("flushing cache via API", func() {
					resp, err := http.Post(baseURL+"/api/cache/flush", "application/json", nil)
					Expect(err).Should(Succeed())
					defer resp.Body.Close()
					Expect(resp.StatusCode).Should(Equal(http.StatusOK))
				})

				By("verifying cache was cleared (TTL reset to full value)", func() {
					msg := util.NewMsgWithQuestion("cached.example.com.", A)
					resp, err := doDNSRequest(ctx, blocky, msg)
					Expect(err).Should(Succeed())
					Expect(resp.Answer).Should(HaveLen(1))
					// After cache flush, TTL should be back near the original value
					Expect(resp.Answer[0].Header().Ttl).Should(BeNumerically(">=", 295))
				})
			})
		})
	})

	Describe("Query endpoint", func() {
		When("HTTP API is enabled", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createDNSMokkaContainer(ctx, "moka", e2eNet,
					`A example.com/NOERROR("A 93.184.216.34 300")`,
				)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
					"ports:",
					"  http: 4000",
				)
				Expect(err).Should(Succeed())
			})

			It("should resolve queries via API", func(ctx context.Context) {
				host, port, err := getContainerHostPort(ctx, blocky, "4000/tcp")
				Expect(err).Should(Succeed())
				baseURL := "http://" + net.JoinHostPort(host, port)

				By("querying an existing domain", func() {
					reqBody, err := json.Marshal(map[string]string{
						"query": "example.com",
						"type":  "A",
					})
					Expect(err).Should(Succeed())

					resp, err := http.Post(baseURL+"/api/query", "application/json", bytes.NewReader(reqBody))
					Expect(err).Should(Succeed())
					defer resp.Body.Close()
					Expect(resp.StatusCode).Should(Equal(http.StatusOK))

					body, err := io.ReadAll(resp.Body)
					Expect(err).Should(Succeed())
					Expect(string(body)).Should(ContainSubstring("93.184.216.34"))
				})

				By("querying a non-existing domain", func() {
					reqBody, err := json.Marshal(map[string]string{
						"query": "nonexistent.example.com",
						"type":  "A",
					})
					Expect(err).Should(Succeed())

					resp, err := http.Post(baseURL+"/api/query", "application/json", bytes.NewReader(reqBody))
					Expect(err).Should(Succeed())
					defer resp.Body.Close()
					Expect(resp.StatusCode).Should(Equal(http.StatusOK))
				})
			})
		})
	})

	Describe("Blocking disable with duration", func() {
		When("blocking is configured", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createDNSMokkaContainer(ctx, "moka", e2eNet,
					`A blocked.com/NOERROR("A 5.6.7.8 300")`,
				)
				Expect(err).Should(Succeed())

				_, err = createHTTPServerContainer(ctx, "httpserver", e2eNet, "list.txt", "blocked.com")
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
					"ports:",
					"  http: 4000",
					"blocking:",
					"  denylists:",
					"    ads:",
					"      - http://httpserver:8080/list.txt",
					"  clientGroupsBlock:",
					"    default:",
					"      - ads",
				)
				Expect(err).Should(Succeed())
			})

			It("should temporarily disable blocking for the specified duration", func(ctx context.Context) {
				host, port, err := getContainerHostPort(ctx, blocky, "4000/tcp")
				Expect(err).Should(Succeed())
				baseURL := "http://" + net.JoinHostPort(host, port)

				By("verifying domain is blocked", func() {
					msg := util.NewMsgWithQuestion("blocked.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(BeDNSRecord("blocked.com.", A, "0.0.0.0"))
				})

				By("disabling blocking for 3 seconds", func() {
					resp, err := http.Get(baseURL + "/api/blocking/disable?duration=3s")
					Expect(err).Should(Succeed())
					defer resp.Body.Close()
					Expect(resp.StatusCode).Should(Equal(http.StatusOK))
				})

				By("verifying domain is unblocked", func() {
					msg := util.NewMsgWithQuestion("blocked.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(BeDNSRecord("blocked.com.", A, "5.6.7.8"))
				})

				By("waiting for duration to expire and verifying blocking is re-enabled", func() {
					Eventually(func() *dns.Msg {
						msg := util.NewMsgWithQuestion("blocked.com.", A)
						resp, _ := doDNSRequest(ctx, blocky, msg)

						return resp
					}, "10s", "500ms").Should(BeDNSRecord("blocked.com.", A, "0.0.0.0"))
				})
			})
		})
	})

	Describe("Blocking disable with groups", func() {
		When("multiple blocking groups are configured", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createDNSMokkaContainer(ctx, "moka", e2eNet,
					`A ads-domain.com/NOERROR("A 5.6.7.8 300")`,
					`A malware-domain.com/NOERROR("A 9.8.7.6 300")`,
				)
				Expect(err).Should(Succeed())

				_, err = createHTTPServerContainer(ctx, "httpserver-ads", e2eNet, "ads-list.txt", "ads-domain.com")
				Expect(err).Should(Succeed())

				_, err = createHTTPServerContainer(ctx, "httpserver-malware", e2eNet, "malware-list.txt", "malware-domain.com")
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
					"ports:",
					"  http: 4000",
					"blocking:",
					"  denylists:",
					"    ads:",
					"      - http://httpserver-ads:8080/ads-list.txt",
					"    malware:",
					"      - http://httpserver-malware:8080/malware-list.txt",
					"  clientGroupsBlock:",
					"    default:",
					"      - ads",
					"      - malware",
				)
				Expect(err).Should(Succeed())
			})

			It("should disable only the specified group", func(ctx context.Context) {
				host, port, err := getContainerHostPort(ctx, blocky, "4000/tcp")
				Expect(err).Should(Succeed())
				baseURL := "http://" + net.JoinHostPort(host, port)

				By("verifying both groups are blocking", func() {
					msg := util.NewMsgWithQuestion("ads-domain.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(BeDNSRecord("ads-domain.com.", A, "0.0.0.0"))

					msg = util.NewMsgWithQuestion("malware-domain.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(BeDNSRecord("malware-domain.com.", A, "0.0.0.0"))
				})

				By("disabling only the ads group", func() {
					resp, err := http.Get(baseURL + "/api/blocking/disable?groups=ads")
					Expect(err).Should(Succeed())
					defer resp.Body.Close()
					Expect(resp.StatusCode).Should(Equal(http.StatusOK))
				})

				By("verifying ads group is unblocked", func() {
					msg := util.NewMsgWithQuestion("ads-domain.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(BeDNSRecord("ads-domain.com.", A, "5.6.7.8"))
				})

				By("verifying malware group is still blocked", func() {
					msg := util.NewMsgWithQuestion("malware-domain.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(BeDNSRecord("malware-domain.com.", A, "0.0.0.0"))
				})

				By("re-enabling blocking", func() {
					resp, err := http.Get(baseURL + "/api/blocking/enable")
					Expect(err).Should(Succeed())
					defer resp.Body.Close()
					Expect(resp.StatusCode).Should(Equal(http.StatusOK))

					msg := util.NewMsgWithQuestion("ads-domain.com.", A)
					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(BeDNSRecord("ads-domain.com.", A, "0.0.0.0"))
				})
			})
		})
	})
})
```

- [ ] **Step 2: Run e2e tests to verify**

Run: `make e2e-test` (or targeted: `go test -v -count=1 -tags e2e -run "API endpoints" ./e2e/...`)
Expected: All tests pass.

- [ ] **Step 3: Commit**

```bash
git add e2e/api_test.go
git commit -m "test(e2e): add API endpoint tests (cache flush, query, blocking duration/groups)"
```

---

### Task 6: `ecs_test.go` — EDNS Client Subnet

Tests ECS as client identifier and ECS forwarding. This is the most complex new test file because it requires manual EDNS0 CLIENT-SUBNET option construction.

**Files:**
- Create: `e2e/ecs_test.go`

**Config reference:** `ECS` struct (`config/ecs.go`), YAML keys: `ecs.useAsClient`, `ecs.forward`, `ecs.ipv4Mask`, `ecs.ipv6Mask`.

**Important notes:**
- ECS options require manual EDNS0 construction on `dns.Msg` using `dns.OPT` and `dns.EDNS0_SUBNET`
- The `HaveEdnsOption` matcher exists in `helpertest/helper.go` for response-side assertions
- ECS forwarding verification is response-side only (mokka cannot inspect incoming EDNS options)

- [ ] **Step 1: Create `ecs_test.go` with ECS helper and all test cases**

```go
package e2e

import (
	"context"
	"net"

	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

// addECSOption adds an EDNS0 CLIENT-SUBNET option to the given DNS message.
func addECSOption(msg *dns.Msg, ip net.IP, mask uint8) {
	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT

	e := new(dns.EDNS0_SUBNET)
	if ip.To4() != nil {
		e.Family = 1 // IPv4
	} else {
		e.Family = 2 // IPv6
	}

	e.SourceNetmask = mask
	e.SourceScope = 0
	e.Address = ip

	o.Option = append(o.Option, e)
	msg.Extra = append(msg.Extra, o)
}

var _ = Describe("EDNS Client Subnet (ECS)", func() {
	var (
		e2eNet *testcontainers.DockerNetwork
		blocky testcontainers.Container
		err    error
	)

	BeforeEach(func(ctx context.Context) {
		e2eNet = getRandomNetwork(ctx)
	})

	Describe("ECS as client identifier", func() {
		When("useAsClient is enabled", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createDNSMokkaContainer(ctx, "moka", e2eNet,
					`A blocked.com/NOERROR("A 5.6.7.8 300")`,
					`A allowed.com/NOERROR("A 1.2.3.4 300")`,
				)
				Expect(err).Should(Succeed())

				_, err = createHTTPServerContainer(ctx, "httpserver", e2eNet, "list.txt", "blocked.com")
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
					"ecs:",
					"  useAsClient: true",
					"  ipv4Mask: 32",
					"blocking:",
					"  denylists:",
					"    ads:",
					"      - http://httpserver:8080/list.txt",
					"  clientGroupsBlock:",
					"    10.0.0.0/8:",
					"      - ads",
				)
				Expect(err).Should(Succeed())
			})

			It("should apply blocking rules based on ECS subnet", func(ctx context.Context) {
				By("blocking domain when ECS IP matches client group", func() {
					msg := util.NewMsgWithQuestion("blocked.com.", A)
					addECSOption(msg, net.ParseIP("10.0.0.1"), 32)

					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(BeDNSRecord("blocked.com.", A, "0.0.0.0"))
				})

				By("allowing domain when ECS IP does not match client group", func() {
					msg := util.NewMsgWithQuestion("blocked.com.", A)
					addECSOption(msg, net.ParseIP("192.168.1.1"), 32)

					Expect(doDNSRequest(ctx, blocky, msg)).
						Should(BeDNSRecord("blocked.com.", A, "5.6.7.8"))
				})
			})
		})
	})

	Describe("ECS forwarding", func() {
		When("forward is enabled", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createDNSMokkaContainer(ctx, "moka", e2eNet,
					`A example.com/NOERROR("A 1.2.3.4 300")`,
				)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
					"ecs:",
					"  forward: true",
					"  ipv4Mask: 24",
				)
				Expect(err).Should(Succeed())
			})

			It("should preserve ECS option in response", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("example.com.", A)
				addECSOption(msg, net.ParseIP("10.1.2.3"), 32)

				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())
				Expect(resp.Answer).ShouldNot(BeEmpty())
				// Verify ECS option is preserved in the response
				Expect(resp).Should(HaveEdnsOption(dns.EDNS0SUBNET))
			})
		})
	})

	Describe("ECS IPv4/IPv6 masks", func() {
		When("custom masks are configured", func() {
			BeforeEach(func(ctx context.Context) {
				_, err = createDNSMokkaContainer(ctx, "moka", e2eNet,
					`A example.com/NOERROR("A 1.2.3.4 300")`,
				)
				Expect(err).Should(Succeed())

				blocky, err = createBlockyContainer(ctx, e2eNet,
					"upstreams:",
					"  groups:",
					"    default:",
					"      - moka",
					"ecs:",
					"  useAsClient: true",
					"  ipv4Mask: 24",
					"  ipv6Mask: 48",
				)
				Expect(err).Should(Succeed())
			})

			It("should apply configured mask to ECS option", func(ctx context.Context) {
				msg := util.NewMsgWithQuestion("example.com.", A)
				addECSOption(msg, net.ParseIP("10.1.2.3"), 32)

				resp, err := doDNSRequest(ctx, blocky, msg)
				Expect(err).Should(Succeed())
				Expect(resp.Answer).ShouldNot(BeEmpty())

				// Verify the ECS option in the response reflects the configured mask (24, not 32)
				opt := resp.IsEdns0()
				Expect(opt).ShouldNot(BeNil())

				var foundECS bool
				for _, o := range opt.Option {
					if subnet, ok := o.(*dns.EDNS0_SUBNET); ok {
						foundECS = true
						Expect(subnet.SourceNetmask).Should(BeNumerically("==", 24))
					}
				}
				Expect(foundECS).Should(BeTrue(), "Response should contain ECS option")
			})
		})
	})
})
```

- [ ] **Step 2: Run e2e tests to verify**

Run: `make e2e-test` (or targeted: `go test -v -count=1 -tags e2e -run "EDNS Client" ./e2e/...`)
Expected: All tests pass.

- [ ] **Step 3: Commit**

```bash
git add e2e/ecs_test.go
git commit -m "test(e2e): add EDNS Client Subnet (ECS) tests"
```

---

### Task 7: Run full e2e suite and verify

Ensure all new and existing tests pass together.

**Files:** None (verification only)

- [ ] **Step 1: Run the full e2e test suite**

Run: `make e2e-test`
Expected: All tests pass, including all pre-existing tests and the 6 new test files.

- [ ] **Step 2: Verify no tests are skipped**

Run: `grep -rn "Pending\|XIt\|XDescribe\|XContext\|XWhen\|Skip(" e2e/*_test.go`
Expected: No matches found.

- [ ] **Step 3: Commit any fixes if needed**

If any tests failed, fix them and commit. If all pass, no action needed.

---

## Phase 2: Test Framework Refactoring

### Task 8: Add `dedent()` helper and update `createBlockyContainer`

Introduce the `dedent` function and change `createBlockyContainer` to accept a single YAML string.

**Files:**
- Modify: `e2e/containers.go` — change `createBlockyContainer` signature, add `dedent()`, update `createTempFile`
- Modify: `e2e/helper.go` — add `dedent` function if preferred location

- [ ] **Step 1: Add `dedent()` function to `e2e/helper.go`**

Add this function at the end of `helper.go`:

```go
// dedent removes common leading whitespace from all lines in a multi-line string.
// This allows writing indented YAML in Go string literals while keeping
// correct YAML formatting after processing.
func dedent(s string) string {
	lines := strings.Split(s, "\n")

	// Find minimum indentation (ignoring empty lines)
	minIndent := -1
	for _, line := range lines {
		trimmed := strings.TrimLeft(line, " \t")
		if len(trimmed) == 0 {
			continue
		}
		indent := len(line) - len(trimmed)
		if minIndent == -1 || indent < minIndent {
			minIndent = indent
		}
	}

	if minIndent <= 0 {
		return s
	}

	// Remove common indentation
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		if len(strings.TrimSpace(line)) == 0 {
			result = append(result, "")
		} else if len(line) >= minIndent {
			result = append(result, line[minIndent:])
		} else {
			result = append(result, line)
		}
	}

	// Trim leading/trailing empty lines
	for len(result) > 0 && result[0] == "" {
		result = result[1:]
	}
	for len(result) > 0 && result[len(result)-1] == "" {
		result = result[:len(result)-1]
	}

	return strings.Join(result, "\n")
}
```

Note: `helper.go` already imports `"strings"` — no import changes needed.

- [ ] **Step 2: Add `createBlockyContainerFromString` alongside existing function**

In `e2e/containers.go`, add a new function that accepts a single YAML string. Keep the existing `createBlockyContainer` with `...string` signature unchanged for now — it will be removed after all callers are migrated. This avoids breaking compilation at any intermediate step.

Add to `e2e/containers.go` (note: `containers.go` already imports `"strings"`):
```go
// createBlockyContainerFromString creates a blocky container with a config provided as a single YAML string.
// It is attached to the test network under the alias 'blocky'.
// It is automatically terminated when the test is finished.
func createBlockyContainerFromString(ctx context.Context, e2eNet *testcontainers.DockerNetwork,
	configYAML string,
) (testcontainers.Container, error) {
	return createBlockyContainer(ctx, e2eNet, strings.Split(configYAML, "\n")...)
}
```

This delegates to the existing function, so there's zero risk.

- [ ] **Step 3: Run e2e tests to verify nothing is broken**

Run: `make e2e-test`
Expected: All tests pass — no existing code was changed.

- [ ] **Step 4: Commit the infrastructure changes**

```bash
git add e2e/containers.go e2e/helper.go
git commit -m "refactor(e2e): add dedent() and createBlockyContainerFromString"
```

---

### Task 9: Add assertion helpers

Add `expectResolve`, `expectNXDomain`, `expectNoAnswer`, `expectRefused`, `expectEventually` to the test framework.

**Files:**
- Create: `e2e/assert_helpers.go`

- [ ] **Step 1: Create `e2e/assert_helpers.go`**

```go
package e2e

import (
	"context"
	"time"

	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	"github.com/testcontainers/testcontainers-go"
)

// expectResolve sends a DNS query and asserts the response matches the expected record.
// Optional extra matchers (e.g., HaveTTL) are applied in addition to BeDNSRecord.
func expectResolve(
	ctx context.Context, blocky testcontainers.Container,
	domain string, qType dns.Type, expected string, extra ...types.GomegaMatcher,
) {
	GinkgoHelper()

	msg := util.NewMsgWithQuestion(domain, qType)

	matchers := []types.GomegaMatcher{BeDNSRecord(domain, qType, expected)}
	matchers = append(matchers, extra...)

	Expect(doDNSRequest(ctx, blocky, msg)).Should(SatisfyAll(matchers...))
}

// expectNXDomain sends a DNS query and asserts the response is NXDOMAIN with no answer.
func expectNXDomain(
	ctx context.Context, blocky testcontainers.Container,
	domain string, qType dns.Type,
) {
	GinkgoHelper()

	msg := util.NewMsgWithQuestion(domain, qType)
	resp, err := doDNSRequest(ctx, blocky, msg)
	Expect(err).Should(Succeed())
	Expect(resp.Rcode).Should(Equal(dns.RcodeNameError))
	Expect(resp.Answer).Should(BeEmpty())
}

// expectNoAnswer sends a DNS query and asserts the response is NOERROR with no answer.
func expectNoAnswer(
	ctx context.Context, blocky testcontainers.Container,
	domain string, qType dns.Type,
) {
	GinkgoHelper()

	msg := util.NewMsgWithQuestion(domain, qType)
	resp, err := doDNSRequest(ctx, blocky, msg)
	Expect(err).Should(Succeed())
	Expect(resp.Rcode).Should(Equal(dns.RcodeSuccess))
	Expect(resp.Answer).Should(BeEmpty())
}

// expectRefused sends a DNS query and asserts the response is REFUSED.
func expectRefused(
	ctx context.Context, blocky testcontainers.Container,
	domain string, qType dns.Type,
) {
	GinkgoHelper()

	msg := util.NewMsgWithQuestion(domain, qType)
	resp, err := doDNSRequest(ctx, blocky, msg)
	Expect(err).Should(Succeed())
	Expect(resp.Rcode).Should(Equal(dns.RcodeRefused))
}

// expectEventually sends a DNS query repeatedly until the expected record is returned.
// Optional extra matchers (e.g., HaveTTL) are applied in addition to BeDNSRecord.
func expectEventually(
	ctx context.Context, blocky testcontainers.Container,
	domain string, qType dns.Type, expected string, timeout time.Duration,
	extra ...types.GomegaMatcher,
) {
	GinkgoHelper()

	msg := util.NewMsgWithQuestion(domain, qType)

	matchers := []types.GomegaMatcher{BeDNSRecord(domain, qType, expected)}
	matchers = append(matchers, extra...)

	Eventually(func() (*dns.Msg, error) {
		return doDNSRequest(ctx, blocky, msg)
	}, timeout, 200*time.Millisecond).Should(SatisfyAll(matchers...))
}
```

- [ ] **Step 2: Run e2e tests to verify compilation**

Run: `make e2e-test`
Expected: All tests pass — new assertion helpers compile and existing tests are unchanged.

- [ ] **Step 3: Commit**

```bash
git add e2e/assert_helpers.go
git commit -m "refactor(e2e): add assertion helper functions"
```

---

### Task 10: Add container setup helpers

Add `mokkaSpec`, `testEnv`, `setupBlockyWithMokka`, `setupBlockyWithHTTPAndMokka`.

**Files:**
- Create: `e2e/setup_helpers.go`

- [ ] **Step 1: Create `e2e/setup_helpers.go`**

```go
package e2e

import (
	"context"

	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
)

// mokkaSpec defines a mock DNS upstream with its network alias and rules.
type mokkaSpec struct {
	alias string   // Docker network alias, used directly in YAML config (e.g., "moka1")
	rules []string // mokka query rules (e.g., `A google/NOERROR("A 1.2.3.4 123")`)
}

// testEnv holds all containers and network for a test scenario.
type testEnv struct {
	network *testcontainers.DockerNetwork
	mokkas  map[string]testcontainers.Container // keyed by alias
	blocky  testcontainers.Container
	httpSrv testcontainers.Container // nil if no HTTP server
}

// setupBlockyWithMokka creates a test network, one or more mokka DNS containers,
// and a blocky container with the given config.
// The mokka aliases (e.g., "moka1") can be referenced directly in the config YAML.
func setupBlockyWithMokka(
	ctx context.Context, mokkas []mokkaSpec, configYAML string,
) *testEnv {
	e2eNet := getRandomNetwork(ctx)

	env := &testEnv{
		network: e2eNet,
		mokkas:  make(map[string]testcontainers.Container, len(mokkas)),
	}

	for _, m := range mokkas {
		c, err := createDNSMokkaContainer(ctx, m.alias, e2eNet, m.rules...)
		Expect(err).Should(Succeed())

		env.mokkas[m.alias] = c
	}

	var err error
	env.blocky, err = createBlockyContainerFromString(ctx, e2eNet, configYAML)
	Expect(err).Should(Succeed())

	return env
}

// setupBlockyWithHTTPAndMokka creates a test network, one or more mokka DNS containers,
// an HTTP static file server serving a single file, and a blocky container.
// The httpAlias (e.g., "httpserver") is the network alias for the HTTP server.
func setupBlockyWithHTTPAndMokka(
	ctx context.Context, mokkas []mokkaSpec,
	httpAlias string, filename string, fileLines []string,
	configYAML string,
) *testEnv {
	e2eNet := getRandomNetwork(ctx)

	env := &testEnv{
		network: e2eNet,
		mokkas:  make(map[string]testcontainers.Container, len(mokkas)),
	}

	for _, m := range mokkas {
		c, err := createDNSMokkaContainer(ctx, m.alias, e2eNet, m.rules...)
		Expect(err).Should(Succeed())

		env.mokkas[m.alias] = c
	}

	var err error
	env.httpSrv, err = createHTTPServerContainer(ctx, httpAlias, e2eNet, filename, fileLines...)
	Expect(err).Should(Succeed())

	env.blocky, err = createBlockyContainerFromString(ctx, e2eNet, configYAML)
	Expect(err).Should(Succeed())

	return env
}
```

- [ ] **Step 2: Run e2e tests to verify compilation**

Run: `make e2e-test`
Expected: All tests pass — setup helpers compile and existing tests are unchanged.

- [ ] **Step 3: Commit**

```bash
git add e2e/setup_helpers.go
git commit -m "refactor(e2e): add container setup helper functions"
```

---

### Task 11: Migrate existing tests to new `createBlockyContainer` signature

Convert all existing test files from `...string` variadic to single `dedent()` string. One commit per file.

**Files to migrate (alphabetical):**
- `e2e/basic_test.go`
- `e2e/blocking_test.go`
- `e2e/bootstrap_test.go`
- `e2e/caching_test.go`
- `e2e/conditional_dns_test.go`
- `e2e/custom_dns_test.go`
- `e2e/dns64_test.go`
- `e2e/dnssec_test.go`
- `e2e/doh_test.go`
- `e2e/integration_test.go`
- `e2e/metrics_test.go`
- `e2e/querylog_test.go`
- `e2e/redis_test.go`
- `e2e/upstream_test.go`

And the 6 new test files:
- `e2e/api_test.go`
- `e2e/ecs_test.go`
- `e2e/fqdn_only_test.go`
- `e2e/filtering_test.go`
- `e2e/hosts_file_test.go`
- `e2e/sudn_test.go`

**Migration pattern:** For each `createBlockyContainer(ctx, e2eNet, line1, line2, ...)` call, convert to:

```go
createBlockyContainerFromString(ctx, e2eNet, dedent(`
    line1
    line2
    ...
`))
```

For lines with string concatenation (e.g., `"      - "+listURL`), use Go string concatenation within the template:
```go
createBlockyContainerFromString(ctx, e2eNet, dedent(`
    upstreams:
      groups:
        default:
          - `+mokaAlias+`
`))
```

- [ ] **Step 1: Migrate each file one at a time**

For each file:
1. Convert all `createBlockyContainer` calls to use `dedent()` with a single string
2. Run `make e2e-test` (or targeted test run for that file)
3. Commit: `git commit -m "refactor(e2e): migrate <filename> to dedent config style"`

Process all 20 files alphabetically. Example transformation for `basic_test.go`:

**Before:**
```go
blocky, err = createBlockyContainer(ctx, e2eNet,
    "upstreams:",
    "  groups:",
    "    default:",
    "      - moka1",
    "ports:",
    "  http: 4000",
    "  dns: 4000",
)
```

**After:**
```go
blocky, err = createBlockyContainerFromString(ctx, e2eNet, dedent(`
    upstreams:
      groups:
        default:
          - moka1
    ports:
      http: 4000
      dns: 4000
`))
```

After all files are migrated, rename `createBlockyContainerFromString` to `createBlockyContainer` (replacing the old variadic version) in a final commit.

- [ ] **Step 2: Run full e2e suite after all migrations**

Run: `make e2e-test`
Expected: All tests pass.

- [ ] **Step 3: Verify no skipped tests**

Run: `grep -rn "Pending\|XIt\|XDescribe\|XContext\|XWhen\|Skip(" e2e/*_test.go`
Expected: No matches found.

---

### Task 12: Final verification

Run the complete test suite and verify everything is clean.

**Files:** None (verification only)

- [ ] **Step 1: Run full e2e suite**

Run: `make e2e-test`
Expected: All tests pass.

- [ ] **Step 2: Verify no skipped tests**

Run: `grep -rn "Pending\|XIt\|XDescribe\|XContext\|XWhen\|Skip(" e2e/*_test.go`
Expected: No matches found.

- [ ] **Step 3: Verify git status is clean**

Run: `git status`
Expected: Working tree is clean, all changes committed.
