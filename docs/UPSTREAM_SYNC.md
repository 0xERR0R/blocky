# Upstream sync plan

Blockasaurus is a fork of [0xERR0R/blocky](https://github.com/0xERR0R/blocky). This document
records the measured state of the divergence, the plan for the next sync, and the set of files
we have intentionally forked so future syncs are cheaper.

Last measured: 2026-09-23, against upstream `main` @ `2bb9b70` (2026-09-21).

## 1. Measured divergence

| Metric | Value |
| --- | --- |
| Merge base | `d459311` (2026-02-27) |
| Commits we are ahead | 211 |
| Commits we are behind | 220 (113 dependency bumps, ~107 substantive) |
| Our diff vs merge base | 214 files, +29,731 / −2,382 |
| Upstream diff vs merge base | 305 files, +39,496 / −5,131 |
| Files both sides touched | 57 |

Reproduce with:

```bash
git remote add upstream https://github.com/0xERR0R/blocky.git
git fetch upstream main
MB=$(git merge-base origin/main upstream/main)
git rev-list --left-right --count $MB...origin/main
git rev-list --left-right --count $MB...upstream/main
```

## 2. Real conflict surface

A trial `git merge upstream/main` was run on 2026-09-23. It produced **41 conflicted paths**:
31 content conflicts and 10 delete/modify conflicts. The remaining 264 upstream-changed files
applied cleanly.

### Content conflicts, by hunk count

| Hunks | File | Nature |
| --- | --- | --- |
| 9 | `go.mod` | Go version + dependency sets. Regenerate, do not hand-merge. |
| 8 | `server/server.go` | **Hard.** Upstream restructured resolver construction and added HTTP/3; we added auth, config store, log broadcaster, stats collector, admin router. |
| 5 | `api/mocks_test.go` | Generated-ish test mocks; regenerate after the API interface settles. |
| 4 | `util/edns0_test.go` | Upstream EDNS0 cookie + OPT-record fixes vs our EDNS0 changes. |
| 4 | `resolver/blocking_resolver.go` | **Hard.** Upstream rewrote client-group matching; we added client-group attribution and group-disable filtering into the same function. |
| 4 | `go.sum` | Regenerate. |
| 4 | `.goreleaser.yml` | Our packaging vs upstream release config. |
| 3 | `config/config.go` | **Hard.** Upstream added per-field doc comments, JSON-schema generation and 4 new config sections; we made `upstreams` YAML-rejecting and added admin ports. |
| 3 | `cmd/root.go` | Upstream added `cache`/`stats` subcommands and API/DNS host+port globals; we removed several subcommands and added `user`. |
| 3 | `README.md` | Branding. Trivial. |
| 3 | `.github/workflows/release.yml` | Our release pipeline. Keep ours. |
| 2 | `server/server_endpoints.go` | **Hard.** Route ownership, including the `/api/stats` collision (§3.1). |
| 2 | `querylog/database_writer_test.go` | Upstream SQLite/dnstap targets. |
| 2 | `e2e/containers.go` | Upstream moved `docker/docker` → `moby/moby/api`. |
| 2 | `docs/configuration.md` | Take upstream, re-apply our sections. |
| 2 | `cmd/serve.go` | Startup wiring. |
| 2 | `api/api_interface_impl.go` | Upstream added the `/stats` operation to the generated API. |
| 2 | `Makefile` | Our web/ui build steps vs upstream tooling bumps. |
| 1 each | `web/index.html`, `server/server_test.go`, `server/http.go`, `resolver/query_logging_resolver.go`, `resolver/metrics_resolver.go`, `metrics/metrics_test.go`, `docs/installation.md`, `docs/index.md`, `docs/config.yml`, `docs/api/openapi.yaml`, `config/upstreams.go`, `cmd/root_test.go`, `api/api_interface_impl_test.go` | Mostly branding or single-site integration. |

### Delete/modify conflicts (10)

We deleted these; upstream still edits them. Resolution for all ten is **re-delete** (`git rm`),
unless a decision in §4 says otherwise.

`.github/workflows/build-bin.yml`, `close_stale.yml`, `codeql-analysis.yml`,
`dependabot-auto-merge.yml`, `development-docker.yml`, `docs.yml`, `goreleaser-test.yml`,
`makefile.yml`, `mirror-repo.yml`, `cmd/lists.go`

Our other intentional deletions (`cmd/blocking.go`, `cmd/cache.go`, `cmd/query.go` and their
tests, `.github/workflows/fork-sync.yml`, `pr-title.yml`) were untouched by upstream and stay
deleted automatically.

### The dangerous set: files that merged *cleanly* but changed semantically

These 16 files were modified by both sides and produced **no conflict markers**. A clean textual
merge here is not evidence of a correct merge — each needs a read of the upstream change against
our change:

`model/models.go`, `querylog/database_writer.go`, `querylog/writer.go`,
`resolver/caching_resolver.go`, `resolver/dnssec/validator.go`, `util/edns0.go`,
`resolver/query_logging_resolver_test.go`, `config/config_test.go`, `e2e/integration_test.go`,
`e2e/metrics_test.go`, `Dockerfile`, `.gitignore`, `docs/additional_information.md`,
`docs/interfaces.md`, `docs/network_configuration.md`, `docs/prometheus_grafana.md`

`resolver/dnssec/validator.go` is the highest-stakes entry: upstream landed a DNSSEC validation
bypass fix there (GHSA-x845-2f78-7v36) plus three other DNSSEC correctness fixes.

**Audited in Phase 4 (GRA-632)** for the Go files in the resolver/querylog/util/metrics/model/cache
set. The check that is worth repeating next sync: for each file both sides touched, diff
merge-base→ours to enumerate our added lines, then assert every one of them is present in the
merged file. On this sync it cleared `model/models.go`, `querylog/database_writer.go`,
`querylog/writer.go`, `resolver/caching_resolver.go`, `resolver/dnssec/validator.go`,
`util/edns0.go` and `resolver/query_logging_resolver_test.go` — each is byte-identical to upstream
apart from exactly our fork delta, which is also what proves the four DNSSEC fixes arrived
verbatim. `resolver/parallel_best_resolver.go` turned out never to have been patched by us, so
upstream's `b73422e` rewrite dropping the `weightedrand` chooser lost nothing of ours; only two
comments and a stale `go.sum` entry still mention it. The one real miss the line-level check does
*not* catch is a semantic reordering — see §4b on `resolver/metrics_resolver.go`, where every one
of our lines survived in the wrong place.

## 3. Why this is more than a textual merge

The original estimate treated the fork as "mostly additive." The trial merge says otherwise in
five specific places. These are the items that actually drive the schedule.

### 3.1 Duplicate statistics subsystems — guaranteed collision

Both sides independently built a stats subsystem in the drift window.

| | Ours | Upstream |
| --- | --- | --- |
| Collector | `pkg/statscollector` | `stats/` |
| Persistence | `configstore/stats.go` (SQLite) | in-memory, 24h window |
| Wiring | `server/server_stats.go` | `resolver/stats_resolver.go` |
| HTTP | `r.Get("/api/stats", …)` plus 7 `/api/stats/*` series routes | generated OpenAPI `GET /stats`, mounted under `/api` |
| CLI | — | `cmd/stats.go` (`blocky stats`) |
| Config | config store | `statistics:` config section |

After the merge both definitions exist. They are different Go packages so the tree still
compiles, but both sides register `GET /api/stats`, and chi panics on a duplicate route pattern
registered on the same router. **This needs an explicit owner decision before resolution starts**
(§4, D1), not an improvised fix at conflict-resolution time.

**Resolved in Phase 5 (GRA-633).** D1 settled it toward ours, so upstream's subsystem was removed
in full rather than left compiling: `stats/`, `resolver/stats_resolver.go` and its spec,
`api.StatsProvider` + `GetStats` + the `toAPI*` mappers, the `/stats` path and its six component
schemas in `docs/api/openapi.yaml`, `config.Statistics` (a knob with no consumer once the
subsystem is gone, so `docs/config.schema.json` loses the `statistics` property), and the three
tests that drove it (`server/stats_client_names_test.go`, `e2e/stats_test.go`,
`e2e/stats_client_names_test.go`). Upstream's `cmd/stats.go` had already gone with the CLI in
Phase 3. `NewStatsResolver` is not chained. `server/chain_wiring_test.go` asserts both halves:
that no resolver named `stats` is in the chain, and that `metricsResolver.StatsCollector` is
actually set — the single assignment the whole dashboard depends on, which no other test noticed
the absence of.

The docs that described upstream's endpoint were rewritten to describe the eight `/api/stats*`
routes this fork serves (`docs/interfaces.md`), and two `#statistics` anchors in
`docs/configuration.md` that pointed at the deleted section were re-pointed. Note one behavioral
difference the old prose hid: upstream's `summary.blocked` unioned `BLOCKED + REBIND`, while
`pkg/statscollector` counts only `BLOCKED`, so rebinding hits show up in the response-type
breakdown rather than as blocks.

### 3.2 Resolver construction was refactored underneath us

Upstream's redis write-through cache refactor (#2025) changed `createQueryResolver` to take a
`resolver.CacheDecorator`, and dropped the `redisClient` parameter from `NewBlockingResolver`.
We pass `redisClient` into `NewBlockingResolver` and a `logstream.Broadcaster` into
`NewQueryLoggingResolver`. Both of our injection points have to be re-established on top of the
new signatures — this is a rewrite of our wiring, not a hunk pick.

**Resolved in Phase 5 (GRA-633).** `createQueryResolver` takes upstream's `CacheDecorator`
alongside our broadcaster and stats collector. `Server.redisClient` is gone — after upstream's
refactor the `redis` package no longer exports a `Client` at all — and nothing was lost with it:
the blocking resolver's `EnabledChannel` pub/sub became `redis.EventBusBridge` (wired into
`server.closers`) and the caching resolver's `redisSubscriber` became
`cache.NewRedisExpiringByteCache`.

The subtlety worth recording, because it is invisible in a diff: the decorator owns goroutines. It
must be built per chain, not once per server. `Server` therefore holds
`newCacheDecorator func(chainCtx context.Context) resolver.CacheDecorator` rather than a bound
decorator, and `Reconfigure` passes its own chain context. A decorator captured at startup would
bind the Redis subscriber and batching writer to the server context, leaking one set — plus the
cache they feed — on every config apply, where pre-merge they died with the chain.

`NewServer`'s routing was also restructured, because upstream's HTTP/3 server and Alt-Svc
middleware had to compose with our `adminPort` split. A single `mainRouter` now names whatever
serves `ports.http`/`ports.https` — the DoH-only router when the admin UI has its own ports, the
full router otherwise — and HTTP/3, which mirrors `ports.https`, serves that same router. The six
`Describe("Admin port mode")` specs pin the split in both directions.

### 3.3 Client-group matching was rewritten in the function we patched

Upstream's #2103 and #2146 replaced the `clientGroupsBlock` map scan with pre-classified
structures (`byID` exact map, parsed CIDR list, FQDN list) and a `scheduledGroup` type from
schedule-based blocking (#2037). We modified that same function to record `request.ClientGroup`
and to filter disabled groups. Our behavior must be re-implemented against upstream's new data
model; taking either side wholesale loses something.

**Resolved in Phase 4 (GRA-632).** Upstream's data model was taken as-is and the attribution
re-implemented on top of it: `cidrGroups` gained an `identifier` field, `collectGroupsForClient`
returns `([]scheduledGroup, string)` where the string is the first matching client identifier, and
`groupsToCheckForClient` assigns it to `request.ClientGroup`. Precedence follows the pre-merge
order — client names (literal before glob), exact IP, CIDR, FQDN — falling back to `"default"`.
The accumulation goes through a `clientMatch` value whose `add` method is inlined and whose
storage stays on the stack, so `BenchmarkBlockingGroupsToCheck{LiteralName,GlobName}` report the
same 200 B / 5 allocs per op as upstream's unpatched version — the point of upstream's rewrite is
preserved. Upstream's new `!r.IsEnabled()` early return in `Resolve` also sets `ClientGroup` to
`"default"`, because pre-merge every request carried a group and the query log and dashboard both
display it. `resolver/blocking_resolver_test.go` ("Client group attribution") pins all of it;
upstream's disabled-group filtering, which now happens inline under a released read lock, replaced
our `isGroupDisabled` helper and its recursive-RLock hazard.

### 3.4 Config ownership is a design conflict

We made `Config.Upstreams` `yaml:"-"` with a sentinel that rejects a legacy `upstreams:` block,
moving upstream configuration into the SQLite config store and the web UI. In the same window
upstream added schema-driven config validation and JSON-schema generation
(`tools/schemagen`, `docs/config.schema.json`, #2066), which reflects over every `Config` field,
plus four new sections (`statistics`, `http3`, `rateLimit`, `rebindingProtection`). Our sentinel
field will flow into the generated schema unless it is handled deliberately.

**Resolved (Phase 3).** `Config.Upstreams` keeps `yaml:"-"` and the `UpstreamsYAML` sentinel
carries `jsonschema:"-"`, which `invopop/jsonschema` honours the same way as a `-` field name.
`docs/config.schema.json` therefore has no `upstreams` property at all, and because the schema
sets `additionalProperties: false`, an `upstreams:` block is reported as an unknown key alongside
the sentinel's migration error. Two specs lock this: `config/schema` asserts the property is
absent, and `config` asserts the loader still rejects the block with a pointer to
`docs/migration-upstreams.md`. Upstream tests that used `upstreams:` merely as a valid-config
vehicle were re-pointed at `customDNS.mapping` / `blocking.denylists`.

### 3.4a The e2e config-store mount may never have been runnable

Recorded in Phase 5, which resolved `e2e/containers.go` but could not run the suite (no Docker in
the runtime). Not merge damage — it predates the sync — but it is the first thing to check when
the e2e gate runs, because it would fail every spec rather than one.

`createBlockyContainerInternal` seeds a SQLite config store on the host and copies it to
`/app/config.db`, and `ensureDatabasePath` points the YAML at that path. `configstore.Open` then
runs `PRAGMA journal_mode=WAL` and treats failure as fatal — and WAL has to *create*
`config.db-wal` and `config.db-shm` siblings in the same directory. `/app` is created implicitly by
`WORKDIR /app` in the `FROM scratch` stage and is root-owned `0755`; only `/app/cache` and `/logs`
are `--chown=100:100`, and the container runs as `USER 100`.

The file mode was the visible half and is fixed: upstream deleted the `modeOwner = 700` constant
(decimal, i.e. `0o1274` — `other = r--`, read-only) in favour of `modeWorldReadable = 0o444`, and
the seeded store now uses `modeWorldWritable = 0o666` since the server opens it read-write. The
directory is the other half. If the suite fails at startup with a SQLite open or WAL error, move
the seed to a writable directory — `/app/cache/config.db` is already `--chown=100:100` for exactly
this kind of use — and pass that path to `ensureDatabasePath`.

**Phase 6 amendment — confirm the premise before applying that recipe.** Phase 6 also had no
container runtime, so the suite still has not been run. But the "root-owned `0755`" claim above is
an assumption, not an observation, and it is the part most likely to be wrong: `USER 100` precedes
`WORKDIR /app` in the Dockerfile, and both the classic builder and BuildKit chown a directory that
`WORKDIR` has to create to the *current* `USER`. If that holds, `/app` is already `100:100`, WAL
creates its siblings fine, and moving the seed to `/app/cache` would be churn that fixes nothing.
So when the gate finally runs: if the suite comes up green, delete this section; if it fails, get
the actual ownership first (`docker run --rm --entrypoint "" -u 0 blockasaurus-e2e ls -ld /app`, or
read the layer metadata) before touching `e2e/upstream_seed.go`.

What Phase 6 *could* establish without Docker: the suite compiles (`go vet ./e2e/`, `go test -c`),
`ginkgo --dry-run --label-filter=e2e` enumerates all 162 specs with no tree errors, and every
`blockasaurus_*` metric name asserted in `e2e/metrics_test.go` resolves to a name the fork actually
registers (`blockasaurus_build_info` comes from `metrics/metrics_event_publisher.go`, not the
`metrics/metrics_test.go` list). So the GRA-632 metrics rename is consistent; what remains unproven
is everything that needs a container to start.

### 3.5 Toolchain and generated-artifact churn

- Go 1.26.1 → 1.26.2; golangci-lint → v2.12.2, with additional linters enabled upstream (#2073).
- `oapi-codegen/runtime` 1.1.2 → 1.7.0 — `api/*.gen.go` must be regenerated, not merged.
- `docker/docker` → `moby/moby/api` in the e2e harness.
- New upstream deps: `quic-go` (DoQ/DoH3), `invopop/jsonschema`, `jedib0t/go-pretty`,
  `dnstap/golang-dnstap`, `pires/go-proxyproto`.
- Generated files to rebuild rather than merge: `api/api_{client,server,types}.gen.go`,
  `docs/config.schema.json`, all `go-enum` outputs (`config/`, `log/`, `lists/`, `model/`,
  `resolver/dnssec/`).

## 3a. Guardrails

Two checks exist so that "did we lose anything?" is a test result rather than a
judgement call. **Run both before the merge and again after every resolution
phase** — a guard that is only consulted at the end tells you something broke
without telling you where.

```bash
go test ./server -run 'TestAPIContract|TestAPISpecContract'
make check-fork-additions
make check-fork-additions-sync   # needs upstream fetched; see below
```

### `TestAPIContract` — routing and auth

`server/api_contract_test.go` builds the real production router
(`createHTTPRouter`, plus `registerDoHEndpoints` for combined-port mode),
wraps it in `withCommonMiddleware` exactly as `newHTTPServer` does, walks it,
and records for every route the method, path pattern and **middleware chain**,
against `server/testdata/api_contract.golden`.

The middleware chain is the part that matters most. Moving a route out of the
authenticated group strips `RequireAuth` without changing its method or path —
the likeliest and most damaging thing a badly resolved `Group` block can do —
and the golden catches it as:

```text
- GET     /api/version    [RequireAuth RequireCSRFHeader RequireAdminForMutations]
+ GET     /api/version    [public]
```

The outermost layer — `secureHeadersMiddleware` and our same-origin CORS policy
in `server/http.go`, which is an upstream file carrying fork edits — is on every
route by construction, so it is recorded once as the `COMMON *` line at the top
of the golden rather than repeated 85 times. Dropping it reads as:

```text
- COMMON  *    [secureHeadersMiddleware Cors.Handler]
+ COMMON  *    [public]
```

### `TestAPISpecContract` — payloads

`server/api_spec_contract_test.go` locks the REST surface as declared in
`docs/api/openapi.yaml` and `docs/api/openapi-config.yaml` against
`server/testdata/api_spec_contract.golden`. `openapi.yaml` is an upstream file
carrying our edits, so it is a prime candidate for being reverted wholesale.

Per operation: its `operationId`, its parameters (name, location, type, enum,
required), and the schema it exchanges in the request body and in each response
by status code. That last part matters on its own — re-pointing
`PUT /custom-dns/{id}` from `CustomDNSEntryInput` to `CustomDNSEntry` changes the
contract without touching either schema.

Per component schema: `type`, `required`, and for every property its type,
format, array item type, enum members, `$ref` target, and composition
(`allOf`/`oneOf`/`additionalProperties`). An array of strings quietly becoming an
array of integers, or an enum losing a member, fails here.

It deliberately ignores prose. Descriptions, summaries, tags and branding will
legitimately change during this merge, and a guard that fires on a reworded
sentence gets regenerated without being read.

### `make check-fork-additions` — file survival

Verifies every path in `.fork-additions` (the 153 files present here and absent
upstream) still exists and is non-empty — `MISSING` for a deleted file, `EMPTY`
for a truncated one. This is what catches a delete/modify conflict resolved
toward upstream. The manifest lists itself, both contract tests and both
goldens, so deleting the guard is itself a failure, and a missing or empty
manifest is a hard error rather than a green "all files present".

`make check-fork-additions-sync` reports when the manifest itself has gone stale
and prints the diff to apply. It needs upstream fetched, and **skips cleanly
when that has not been done** — if you see it compare the manifest against an
empty upstream tree and recommend adding hundreds of files, do not follow that
advice: it would pad the manifest with the whole upstream tree and turn
`check-fork-additions` into a tautology.

```bash
git remote add upstream https://github.com/0xERR0R/blocky.git
git fetch upstream main
make check-fork-additions-sync
```

### Reading a golden diff

A diff is never automatically a bug — but it is always a change to the contract
`web/ui` and any API consumer depend on. Four legitimate reasons to regenerate:

1. We deliberately added an endpoint.
2. We deliberately removed one, and the UI no longer calls it.
3. An upstream fix changed a schema we decided to adopt.
4. The *recording* changed without the surface changing — `TestAPIContract` reads
   the router through `chi.Walk`, so a chi upgrade can alter what gets reported
   for routes nobody touched. Phase 5 hit both halves of this: chi 5.3 began
   reporting a mounted sub-router's parent middleware (the `/debug/*` rows gained
   `RequireAuth RequireCSRFHeader` they always had at runtime), and it added
   `QUERY` to its `mALL`, which broke the `ANY` collapse until `allMethods` in
   `api_contract_test.go` followed. This is the reason most easily mistaken for
   the merge eating our work, so **prove it**: a reporting change never removes a
   route and never *drops* a guard, and the runtime behavior should be
   demonstrable with a request rather than argued from the diff.

Anything else is the merge eating our work. An upstream route that merged cleanly
is not on this list: drop it, or record an owner decision in §4 (see D7 for the
one time that happened). Regenerate only with:

```bash
go test ./server -run 'TestAPIContract|TestAPISpecContract' -update-api-contract
```

and call the change out explicitly in the pull request.

### What the guardrails do not cover

Say this out loud so nobody trusts them further than they reach:

- **Fork edits to upstream files.** `.fork-additions` only catches deletions of
  fork-*only* files. The likelier casualty in a 220-commit merge is one of the
  ~18 upstream files carrying our patches (§7) being reverted by a sloppy hunk
  resolution. Two of those files — `server/server_endpoints.go` and
  `server/http.go` — are now covered for their routing and middleware content by
  `TestAPIContract`. The rest are not: that is what the §7 register and a
  `git diff` against the pre-merge tag are for.
- **Handler behavior.** `TestAPISpecContract` reads the spec, not the code.
  Nothing proves a handler honors the schema it advertises, or that the spec
  describes what the handler really returns. Likewise `TestAPIContract` records
  the identity and order of a middleware chain, never what it does.
- **`components.parameters` and `components.responses`.** Recorded where an
  operation references one by name, so a re-pointed reference fails — but the
  contents behind that name are not locked.
- **The split-router arrangement.** With `ports.httpAdmin`/`httpsAdmin` set,
  `NewServer` builds two routers and serves the admin UI separately from DoH.
  The test unions both registration functions onto one mux, so route coverage is
  equivalent but the *split* is not pinned: a merge that mounted the UI routes on
  the DoH listener would not fail here.
- **The Svelte UI.** Only that its files still exist and that it builds.
- **Anything undocumented.** A field the UI relies on that the spec never
  mentions is invisible to the payload guard by construction.

### Where these run

`check-fork-additions` is a prerequisite of `make test`, and
`.github/workflows/ci.yml` runs both it and the full non-e2e suite on every pull
request and every push to `main`. Before that workflow existed, this repo had
only the tag-triggered `release.yml`, which runs no tests — so "the merge fails
the build" meant "the merge fails if someone remembers to run the suite
locally". If you delete or disable that workflow, these guardrails go back to
being a convention.

## 4. Decisions — settled

Owner decisions, made 2026-09-23. Recorded here because resolving these at
conflict time produces arbitrary outcomes.

| # | Decision | Outcome |
| --- | --- | --- |
| D1 | Stats subsystem ownership | **Keep ours.** `pkg/statscollector` + `configstore/stats.go` + `server/server_stats.go` back the dashboard's overtime, top-clients and latency series, which upstream's in-memory 24h collector does not provide. Upstream's `/stats` operation must not reach the router — drop `stats/`, `resolver/stats_resolver.go`, `cmd/stats.go` and the `/stats` path from the spec, or keep the package unwired. |
| D2 | `upstreams:` YAML sentinel | **Keep rejecting.** Upstream configuration stays in the SQLite config store. Exclude the sentinel field from upstream's generated JSON schema. |
| D3 | `cmd/lists.go`, `cache` / `stats` subcommands | **Re-delete.** These are UI-driven in Blockasaurus. |
| D4 | The 9 upstream GitHub workflows | **Re-delete.** |
| D5 | New upstream features | **Merge the code at upstream defaults; no config-store or UI plumbing during the sync.** DoQ and DoH3 get UI work as dedicated follow-ups immediately after the sync lands (GRA-638, GRA-639). The remainder stay YAML-only until someone asks for them; see §4a. |
| D6 | `docs/` branding | Take upstream content, re-apply Blockasaurus branding as a final pass. |
| D7 | `GET /docs/config.schema.json` | **Provisionally accepted in Phase 5, pending owner confirmation.** See below — this is the one upstream route the sync adds to our HTTP surface, and §3a's rule is that such a route is dropped, not accepted. |

### D7 — the one upstream route this sync adds

`configureDocsHandler` merged cleanly and brought a new route with it:

```text
+ GET     /docs/config.schema.json                      [RequireAuth RequireCSRFHeader]
```

Accepted rather than dropped, on the following reasoning — but **it is the owner's call, not the
resolver's**, which is why it is written down here instead of being absorbed:

- The config JSON schema feature is already adopted elsewhere in this sync. `config/schema/embed.go`
  embeds `docs.ConfigSchema` and validates every loaded config against it, and §3.4's D2 resolution
  turns on `docs/config.schema.json` being generated and current. Serving the same artifact over
  HTTP is the companion, not a new capability.
- Two specs that arrived with the merge cover the route, so dropping it means deleting upstream
  tests as well as upstream code.
- It is read-only and inside the authenticated group, serves a checked-in generated artifact with
  no secrets, and collides with nothing.
- `TestAPIContract`'s golden had to be regenerated in this phase regardless, for an unrelated and
  entirely non-behavioral reason (chi 5.3 reports a mounted sub-router's parent middleware, so the
  `/debug/*` rows gained guards they always had at runtime). So keeping the route does not cost a
  golden change that would otherwise have been avoided.

**To reverse it** — drop `router.Get("/docs/config.schema.json", …)` from `configureDocsHandler`
and its link from `configureRootHandler` in `server/server_endpoints.go`, re-point
`server/server_test.go`'s "Docs endpoints" and PROXY-protocol specs at `/docs/openapi.yaml`, and
rerun `go test ./server -run TestAPIContract -update-api-contract`.

### 4a. Merged but not surfaced — and what happens to each

These land in the tree as part of the sync and sit at upstream defaults — off,
unless the operator sets them in YAML. None of them changes behavior by merging.
The Disposition column records the owner's call (2026-09-23) so a future reader
knows the capability exists, and whether it was wanted, without rediscovering it
in a diff.

| Feature | What it does | Default | Disposition |
| --- | --- | --- | --- |
| Per-client rate limiting (#2063) | Token bucket per client IP, with configurable rate, burst, IPv4/IPv6 aggregation prefix and an allowlist. | `enable: false` | No issue filed — available if something on the LAN misbehaves. |
| DNS rebinding protection (#2111) | Rejects upstream answers that map a public name to a private address, with a per-domain allowlist for the NAS-on-a-real-hostname case. | `enable: false` | **Wanted.** GRA-641. |
| PROXY protocol (#2094) | Accepts HAProxy PROXY headers on proxied DoT/DoH listeners so the real client IP survives a reverse proxy. Relevant behind k8s ingress, where client-group matching otherwise sees the proxy. | opt-in per listener | Declined for now — not needed. |
| SQLite query log (#2080) | Query log to a local SQLite file — no external database. | existing `queryLog.type` | See §4b. |
| dnstap query log (#2144) | Query log as a dnstap stream for external collectors. | existing `queryLog.type` | See §4b. |
| Query-log domain ignore (#2084) | Exclude domains (exact, wildcard, regex) from the query log. | none configured | See §4b. |
| Schedule-based blocking (#2037) | Time-of-day and weekday windows for deny/allowlist groups, including overnight ranges. Pairs naturally with the existing client-groups UI. | no schedules configured | **Wanted in the UI.** GRA-640. |
| On-disk list download cache (#2087) | Caches downloaded blocklists on disk with conditional revalidation, so restarts do not re-download every list. | opt-in | **Wanted.** GRA-642. |
| Config values from files (#2077) | Reads sensitive config values from files instead of inline YAML. | unused | No issue filed. |
| Config folder structural merge (#2112) | Merges multiple config files in a folder structurally rather than by last-wins. | unchanged behavior | No issue filed — behavior unchanged. |

### 4b. Query logging as it stands

Recorded because the answer is not obvious from the code and the constraint
below will bite whoever changes `queryLog.type` first.

Today: `queryLog.type: console`. Query entries go to the pod's stdout **and**,
separately, to the `logstream.Broadcaster` that feeds the UI's Logs page over
`/api/ws/logs`. The broadcaster is a 1000-entry ring buffer — live tail only,
no history, nothing survives a restart.

**The constraint.** `NewQueryLoggingResolver` only attaches the broadcaster when
the selected writer is a `*querylog.LoggerWriter`:

```go
if lw, ok := writer.(*querylog.LoggerWriter); ok && broadcaster != nil {
    lw.SetBroadcaster(broadcaster)
}
```

`queryLog.type` is single-valued, so selecting any non-console target — csv,
mysql, sqlite, dnstap — silently turns the UI's live query log off. Anyone
adopting a new target should first move the broadcaster publish out of the
console writer and into the query-logging resolver, so the UI stream is
independent of the storage target.

Upstream's new targets in this sync: `sqlite` (local file, queryable history),
`dnstap` (Frame Streams over `unix:/path` or `tcp://host:port`), and
`queryLog.ignore` for excluding domains by exact match, wildcard or regex. Note
that `log.privacy` obfuscation does **not** apply to dnstap payloads — it
exports full wire-format DNS messages.

**The dashboard does not depend on any of this.** Nothing the admin UI shows is
derived from the query log, so changing `queryLog.type` — including setting it
to `none` — leaves every stat intact. Two independent sources feed it, both off
the resolver chain:

- The three headline cards (`/api/stats`) gather from the in-process Prometheus
  registry. `MetricsResolver.Resolve` only increments those counters inside
  `if r.cfg.Enable`, so they need `prometheus.enable: true`, and they reset on
  restart.
- Everything else — over-time series, top domains, top clients, query types,
  response types, latency (`/api/stats/*`) — comes from `pkg/statscollector`.
  `MetricsResolver` calls `StatsCollector.Record` **outside** the Prometheus
  guard, so this collects regardless of that flag, and `configstore/stats.go`
  flushes it to SQLite every 30s and reloads at startup. These survive restarts.

  Upstream's `77b0fe7` turned that guard into an early return, which silently put the
  `Record` call behind it and emptied every series above whenever `prometheus.enable`
  was false. Phase 4 hoisted it into `MetricsResolver.recordStats`, called before the
  early return, and pinned the independence with a test
  (`resolver/metrics_resolver_test.go`, "Feeding the dashboard stats collector"). Keep
  that call above the guard.

What the query log alone gives you is durable per-query history — which client
asked for which name at which time. The dashboard's aggregates are not a
substitute for that, and it is the only thing lost by leaving query logging on
`console`.

**Searching by client and domain.** The owner wants this in the **live log
viewer**, not in an external log pipeline (2026-09-23). Blockasaurus is a
self-contained home DNS server in the Pi-hole mould; shipping DNS logs to the
cluster's OpenSearch was explicitly rejected, and an earlier issue proposing it
is cancelled.

That makes it a frontend change and nothing more (GRA-645).
`Broadcaster.Subscribe` backfills from a 1000-entry ring before streaming live,
so the viewer already holds recent history; the entries already carry
`client_ip`, `client_group`, `question_name`, `question_type`, `response_code`
and `response_reason`; and chonky-ui's `LogViewer` has no filtering of its own,
so a derived filtered list in `Logs.svelte` is the whole feature. No API, no
storage, no config change, no contract-golden regeneration.

Persistent query history — the `sqlite` target, a query API, a history page — is
**not** being built. The live buffer is the scope. If that ever changes, the
broadcaster coupling above has to be fixed first (GRA-644).

dnstap is not wanted either: it exports wire-format DNS messages for external
collectors, which is forensics for a pipeline we are deliberately not building.
It stays merged and unused, as does the `sqlite` target.


## 5. Plan

Each phase ends at a gate. Do not start a phase before its gate passes.

| Phase | Work | Gate | Est. |
| --- | --- | --- | --- |
| 0. Baseline | Tag `pre-upstream-sync-v0.34.38`. Add the §3a guardrails. Record current behavior: `go test ./...`, e2e suite, and a captured set of DNS answers (blocked/allowed/custom/conditional/DNSSEC/EDNS0) plus dashboard screenshots. This is what "did we regress?" is measured against later. | Guardrails green. Baseline recorded in `docs/upstream-sync/baseline-v0.34.38.md` — **not** `scratch/`, which is gitignored and would not survive to be compared against. | 0.5d |
| 1. Decisions | Close D1–D6 in §4. | Written answers on the sync issue. | — |
| 2. Merge + mechanical | Branch `sync/upstream-2026-09`. `git merge upstream/main`. Resolve in order: `go.mod`/`go.sum` (regenerate), workflows (re-delete), `cmd/lists.go` (re-delete), `.goreleaser.yml`/`Makefile`/`README`/`web/index.html` (keep ours + branding), `docs/*` (take upstream). | Only the Go integration conflicts remain unresolved. | 0.5d |
| 3. Config + CLI | `config/config.go`, `config/upstreams.go`, `cmd/root.go`, `cmd/serve.go`. Regenerate enums and `docs/config.schema.json`. | `go build ./config/... ./cmd/...`, config tests green. | 1d |
| 4. Resolver chain | `resolver/blocking_resolver.go`, `metrics_resolver.go`, `query_logging_resolver.go`, plus semantic review of the cleanly-merged `caching_resolver.go`, `dnssec/validator.go`, `querylog/*`, `util/edns0.go`, `model/models.go`. Re-establish our redis and broadcaster injection against upstream's new signatures (§3.2) and our client-group attribution against upstream's new matcher (§3.3). | `go test ./resolver/... ./querylog/... ./util/...` green. | 2–3d |
| 5. Server + API | `server/server.go`, `http.go`, `server_endpoints.go`. Reconcile admin ports and the UI router with upstream's HTTP/3 and PROXY-protocol listeners. Apply D1. Regenerate `api/*.gen.go` and mocks. | `go build ./...`, `go test ./server/... ./api/...` green. Server starts without a route-registration panic. | 1–1.5d |
| 6. Full verification | `go test ./...`, e2e suite, lint at upstream's v2.12.2 ruleset, `web/ui` build. | All green. | 0.5–1d |
| 7. Behavioral smoke | Replay the Phase 0 DNS capture and diff. Manually exercise: login/session, dashboard, client groups, domain entries, blocklists, upstream groups, users, query log stream. | No unexplained delta vs Phase 0. **Done — `docs/upstream-sync/behavioral-replay-2026-09.md`.** Phase 0 left no capture to replay, so both trees were built and run side by side instead; six deltas, all attributable. | 0.5d |
| 8. Port checklist | Walk §6 and confirm each upstream fix is actually present and effective in the merged tree. | Checklist complete. | 0.5d |
| 9. Land | PR, review, merge. Update this document's "Last measured" line and §7. | Merged. | 0.5d |

**Estimate: 7–9 focused days.** The earlier 3–4 day estimate assumed the fork was additive; the
trial merge shows three of our integration points sit inside code upstream refactored (§3.2–3.4),
which is where the extra time goes. Phases 4 and 5 carry essentially all of the schedule risk.

## 6. Upstream port checklist

Verify each of these is present *and effective* in the merged tree — several land in files where
our version won the conflict.

Six are already ticked: Phase 7's side-by-side replay observed each one changing the wire answer
between the pre-merge binary and post-merge `main`, which is stronger than reading the diff.
Evidence per item is in `docs/upstream-sync/behavioral-replay-2026-09.md` §3. The rest are still
open and belong to the port-checklist phase.

**Security / correctness (must-have)**

- [ ] `2496d12` DNSSEC validation bypass & cache-scope pollution — GHSA-x845-2f78-7v36
- [ ] `a191ad2` DNSSEC: propagate Indeterminate, not Bogus, for unreachable chain of trust
- [ ] `d3a1fe5` DNSSEC: don't cache transient Indeterminate results
- [ ] `fc353a0` DNSSEC: only validate public-upstream answers
- [ ] `a42d656` DNSSEC: don't return records to clients with the DO bit clear
- [ ] `2ffe18a` RFC 4034 canonical name ordering for NSEC coverage
- [ ] `e0ea9b3` eliminate recursive RLock deadlock in blocking group resolution

**Protocol fixes**

- [x] `78d5367` don't pass EDNS0 DNS cookies through — replay §3
- [x] `ff2aae4` always answer an EDNS0 query with an OPT record — replay §3
- [x] `2e5d478` NOTFQDN → well-formed NXDOMAIN — replay §3
- [x] `802869a` SOA record on custom-DNS NOERROR — replay §3
- [ ] `c46ed64` retry DoH queries failing on a stale pooled connection
- [ ] `db8d889` compress responses larger than 512 bytes
- [x] `190d512` count down cached authority/additional TTLs — replay §3
- [ ] `1d450af` case-insensitive custom-DNS PTR matching
- [ ] `91a8f44` bootstrap: fall back to other resolved addresses on dial failure
- [ ] `e2b40db` / `dcdd952` rewritten-query handling: original name to next resolver, fallbackUpstream

**Blocking / resolver behavior**

- [x] `344de86` scope allowlist-only mode to the whole client — replay §3
- [ ] `769d908` `refused` block type
- [ ] `4b524e8` ECS `useAsClient` applied above cache and client-name lookup
- [ ] `c851293` log the matched rule in the block reason
- [ ] `99ae703` filter `ipv6hint` in HTTPS/SVCB when AAAA is filtered

**Metrics / performance**

- [ ] `7dd039c` `blocky_client_response_total` metric
- [ ] `77b0fe7` avoid per-query label map allocations in the metrics resolver
- [ ] `06555e0` bound reason label cardinality for blocked responses
- [ ] `b73422e` allocation-free resolver selection in `ParallelBestResolver`
- [ ] `316b073` pre-classify client groups
- [ ] `6da7ce1` lock-free grouped cache, cheapest-first lookup
- [ ] `87be127` sharded result cache
- [ ] `302ca65` cut per-request logger allocations
- [ ] `223df0c` skip per-request LogEntry build when query log is off

**Features (merge; enablement is D5)**

- [ ] `c32863d` DoQ upstream, `842dda9` DoH3, `1b8e08a` DoT pooling, `bee2d8b` UDP-first plain DNS
- [ ] `e6b41db` per-client rate limiting, `0b70e5c` rebinding protection, `7abca44` PROXY protocol
- [ ] `e43b5e5` SQLite query log, `e9deb53` dnstap query log, `b82199b` query-log domain ignore
- [ ] `22b0bdd` schedule-based blocking, `e7958e0` on-disk list download cache
- [ ] `c44017a` sensitive config values from files, `7c6da15` config-folder structural merge
- [ ] `fdcf351` client names from hosts file and custom DNS, `f457ec9` `resolvFile` bootstrap
- [ ] `0de3fac` `resolver.arpa` / DDR per RFC 9462
- [ ] `4cf62ce` healthcheck follows `ports.dns`

## 7. What we have intentionally forked

Keep this current — it is what makes the *next* sync cheap.

**Additive, no upstream contact (safe):** `web/ui/` (Svelte SPA), `auth/`, `configstore/`,
`logstream/`, `pkg/statscollector/`, `packaging/`, `assets/`, `VERSION`,
`Dockerfile.goreleaser`, `api/configapi/`, `cmd/user.go`, `server/server_stats.go`.

**Upstream files we carry patches in (the recurring cost):** `config/config.go`,
`config/upstreams.go`, `cmd/root.go`, `cmd/serve.go`, `server/server.go`, `server/http.go`,
`server/server_endpoints.go`, `api/api_interface_impl.go`, `resolver/blocking_resolver.go`,
`resolver/query_logging_resolver.go`, `resolver/metrics_resolver.go`, `querylog/writer.go`,
`model/models.go`, `util/edns0.go`, `web/index.html`, `Makefile`, `.goreleaser.yml`,
`.github/workflows/release.yml`.

Plus the files patched **only** to carry the metric prefix: `resolver/caching_resolver.go`,
`resolver/dnssec/validator.go`, `resolver/rate_limiting_resolver.go`,
`metrics/metrics_event_publisher.go`, `querylog/dnstap_writer.go`, `cache/redis.go`,
`metrics/metrics_test.go`, `e2e/metrics_test.go`.

**Deliberately deleted:** `cmd/blocking.go`, `cmd/cache.go`, `cmd/lists.go`, `cmd/query.go`
(+ tests) — replaced by the web UI. Upstream CI workflows other than `release.yml`.

**Design divergences:** upstream configuration lives in the SQLite config store, not YAML
(`upstreams:` is rejected); admin UI runs on its own listeners (`adminPort`, `adminPortTLS`);
statistics are persisted rather than in-memory; every Prometheus metric is named
`blockasaurus_*`, so each upstream sync has to rename the metrics upstream added (this one brought
`client_response_total`, `redis_cache_buffer_drops_total`, `dnstap_frames_dropped_total` and the
three `rate_limit_*` metrics). `metrics/metrics_test.go` is the gate: it fails on any registered
metric missing from its expected list, in either direction.

## 8. Cadence

Seven months of drift is what turned this into a week of work. Sync every 4–6 weeks:

```bash
git fetch upstream main
git merge upstream/main
```

At that cadence each merge should be a handful of conflicts in the §7 patched-file list. After
every sync, update §7 and the "Last measured" line at the top.

Capture the behavioral "before" *first*, with the old binary still running — this sync's Phase 0
skipped it and Phase 7 had to rebuild the pre-merge tree to recover it:

```bash
go run ./tools/dnsreplay 127.0.0.1:53 > before.txt   # then again after the merge, and diff
```

Seed the config store before capturing and restart once afterwards. The store's YAML sections are
replaced by DB state at load, and the `default` client group's group list is repaired at open, so
an unseeded or un-restarted instance is not measuring the configuration you think it is.

## 9. Lint baseline at golangci-lint v2.12.2

Upstream's `2073` enabled a much larger linter set and `2062` moved the pin to `v2.12.2`
(`GOLANG_LINT_VERSION` in the Makefile — `make lint` `go run`s that exact version, so whatever is
on `PATH` is irrelevant). The fork's own packages had never been run against either. The first run
after the sync reported **245 issues**.

`make lint` is not a CI gate: `.github/workflows/ci.yml` runs the frontend build, `go build ./...`
and `make test`. Lint is a local gate, which is why this drift accumulated silently.

Of the 245, only six files with findings are shared with upstream — `cmd/cmd_suite_test.go`,
`cmd/serve.go`, `config/config.go`, `resolver/blocking_resolver.go`, `server/server.go`,
`server/server_endpoints.go` — and every finding in them is a style rule (`funlen`, `lll`, `mnd`,
`goconst`, `tagalign`), not a merge artifact. **No lint finding is attributable to the merge.**

### Cleared

91 findings were fixed in the Phase 6 verification commit: the `--fix`-able mechanical set
(`tagalign`, `misspell`, `modernize`, `copyloopvar`, `intrange`, `perfsprint`, `nlreturn`,
`whitespace`, `unconvert`, `nolintlint`), plus by hand `nosprintfhostport` in `pkg/advertise`
(an IPv6 `KUBERNETES_SERVICE_HOST` would have produced a malformed API-server URL), a dead
no-op loop in `e2e/upstream_seed.go`, four dead helpers, the inert `omitempty` on
`userResponse.CreatedAt`, and the `errcheck` / `errorlint` / `testifylint` findings.

gosec's two G115 findings on the custom-DNS TTL turned out to be real rather than noise: the
wire type is a plain `integer` with `minimum: 0` and no maximum, nothing enforced that bound at
runtime, and the store field is a `uint32` — so `ttl: 4294967296` wrapped to 0 on the way in.
`validateCustomDNSEntry` now rejects anything outside `[0, MaxUint32]`, the conversions carry a
`//nolint:gosec` pointing at that check, and there is a spec for it.

`modernize` inlined `configstore.BoolPtr` into `new(v)` at every call site, which left the helper
dead; it was removed.

### Left, and why — 154 findings

| Linter | N | Disposition |
| --- | --- | --- |
| `staticcheck` | 22 | All SA1019: `nhooyr.io/websocket` is deprecated in favour of `github.com/coder/websocket`. **Not** a drop-in version bump — the fork's latest tag is `v1.8.15` and we are on `nhooyr.io/websocket v1.8.17`, so migrating moves *backwards* in version. Four files: `logstream/handler.go`, `logstream/handler_test.go`, `auth/wsrevoke.go`, `server/server_endpoints.go`. Worth its own change with the websocket paths actually exercised; not a verification-phase edit. |
| `nilerr` | 19 | 18 are `api/configapi/handler.go` and structural: oapi-codegen's strict-handler pattern returns a typed `404`/`400` response value *and* a nil error, which is exactly what `nilerr` flags. The remaining one is `configstore/store.go:292`. |
| `lll` | 29 | 13 in `api/configapi/handler.go`, the rest scattered. Generated-shaped handler signatures; wrapping them buys nothing. |
| `funlen` / `gocognit` / `nestif` | 21 | `NewServer`, `runServer`, `Reconfigure`, `registerUIRoutes` and the configstore CRUD bodies. Splitting these is a refactor, not a lint fix, and `server.go` is the single worst file to churn between syncs. |
| `goconst` | 20 | Mostly `"default"`, `"A"`, `"admin"` repeated across the configstore and API layers. A shared constant would be an improvement; it is a fork-wide rename, not sync work. |
| `mnd` | 13 | Timeouts, buffer sizes, HTTP ports. |
| `gosec` | 6 | Triaged as safe: 3× G124 cookies — the session cookie sets `HttpOnly` and `SameSite` and sets `Secure` only when the request is TLS, because the admin UI is reachable over plain HTTP on a LAN; G101 on a Kubernetes service-account *path* constant; 2× G704 "SSRF" on the in-cluster API-server URL built from `KUBERNETES_SERVICE_HOST`. |
| `errchkjson` | 5 | Response-body encoders written after the status line is already committed, using the file-local `_ = json.NewEncoder(w).Encode(...)` idiom. `errchkjson` rejects the blank assignment for `any`-typed payloads specifically; there is nothing useful to do with the error at that point. |
| `noctx` | 5 | 3 in `auth/middleware_test.go`/`server_auth_test.go` (`httptest.NewRequest`), 1 `net.Dial` in `pkg/advertise/detect.go` (outbound-IP probe, already dial-timeout bound), 1 `net.LookupAddr` in `server_endpoints.go`. |
| `contextcheck` | 4 | Deliberate: shutdown and reconfigure paths intentionally build a fresh context so a cancelled request context cannot abort them. |
| `gochecknoglobals` | 3 | `trustedProxyNets`, `mobileconfigNamespace`, `mobileconfigTmpl` — package-level constants in all but name. |
| `unparam` | 2 | Test helpers (`seedUser`, `login`) whose extra parameter documents intent. |
| `dupl` | 2 | `configstore/store.go:186-217` vs `configstore/upstreams.go:40-71`. Real duplication, worth folding, out of scope here. |
| `containedctx` | 1 | `logstream/broadcaster.go` stores the subscriber's context so a dropped websocket unsubscribes. |
| `forcetypeassert` | 1 | `server_auth.go:141` — the `sync.Map` is written at exactly one site, always with `*loginBucket`. A checked assertion adds an unreachable branch. |
| `nilnil` | 1 | `configstore/stats.go:109`. |

Reproduce with `make lint`. If the count moves without this table moving, something changed.
