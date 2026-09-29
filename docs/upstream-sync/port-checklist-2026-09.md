# Upstream port checklist — evidence

This is the Phase 8 half of `docs/UPSTREAM_SYNC.md` §5: proof that every upstream fix listed in
§6 is not merely *in the history* — a merge makes that trivially true — but present in the code
path a query actually takes, and effective.

| | |
| --- | --- |
| Tree | `main` → `5fe086e` (PR #9 merged) |
| Upstream ref the merge brought in | `2bb9b70` (`git merge upstream/main`, commit `6960b94`) |
| Measured | 2026-09-29 |
| Go | go1.26.4 linux/amd64 |

## How each item was settled

Three kinds of evidence, in descending order of strength. Every row in §3–§6 below says which one
it rests on.

- **probe** — a running instance answered a query (or served a metric, or wrote a log row) that
  distinguishes the fixed behavior from the unfixed behavior. This is the only evidence that
  cannot be wrong about the code path.
- **bench** — the upstream benchmark the fix was written against, run here and against upstream
  `2bb9b70` itself, with identical allocation counts. For the performance items "effective" *is*
  an allocation number, so parity with upstream is the measurement.
- **code path** — the file is byte-identical to `2bb9b70`, the upstream test that covers the fix is
  byte-identical and passing, and the caller that reaches it was read. Three items rest on this;
  the one where a live probe is not constructible here says why.

Nothing is closed on "the commit is an ancestor of HEAD". Every commit on the checklist is one,
because a merge makes it so; that is exactly why it proves nothing about conflict resolution.

Of the 50 items in §6, 6 were already closed by the Phase 7 replay. Of the 44 that were open, 41
are settled below by probe or benchmark. Three rest on code path: `e0ea9b3` (settled earlier by
GRA-632/634), `77b0fe7` (no benchmark of its own, and the change is the absence of an allocation in
a read of nine lines), and `c46ed64` — the only item where a live probe is not constructible here,
with the reason in its row.

## 1. File-level survival

The merge's conflict resolution is the only thing that can silently undo an upstream fix, so start
there. The 44 commits on the checklist touch 78 non-test Go files that exist in this tree;
**63 are byte-identical to `2bb9b70`** and therefore carry their upstream code verbatim.

```bash
git diff --numstat 2bb9b70 HEAD -- <file>
```

All 15 that differ are already on §7's "upstream files we carry patches in" list — no file the
merge touched drifted without being accounted for there:

| File | Δ | Fork delta |
| --- | --- | --- |
| `resolver/dnssec/validator.go` | +3 −3 | three `blocky_` → `blockasaurus_` metric names |
| `resolver/caching_resolver.go` | +2 −2 | metric names |
| `resolver/rate_limiting_resolver.go` | +3 −3 | metric names |
| `querylog/dnstap_writer.go` | +1 −1 | metric name |
| `model/models.go` | +1 | `Request.ClientGroup` |
| `querylog/writer.go` | +1 | `ClientGroup` on the log entry |
| `querylog/database_writer.go` | +2 | `client_group` column |
| `resolver/query_logging_resolver.go` | +11 −1 | logstream broadcaster injection, `ClientGroup` |
| `config/upstreams.go` | +13 | the `upstreams:` YAML rejection sentinel |
| `config/config.go` | +34 −6 | fork config: `databasePath`, admin ports, client-group endpoints |
| `cmd/root.go` | +5 −62 | the deleted `blocking`/`cache`/`lists`/`query` subcommands |
| `e2e/containers.go` | +28 −1 | fork e2e image wiring |
| `resolver/blocking_resolver.go` | +44 −13 | client-group attribution (`clientMatch`) through `collectGroupsForClient`; `request.ClientGroup` on the disabled path |
| `resolver/metrics_resolver.go` | +47 −5 | `recordStats` for the dashboard collector, five metric names |
| `server/server.go` | +341 −42 | chain hot-swap, admin listeners, auth/stats/logstream wiring |

Six of those 15 carry a §6 fix's own code, so each was read line by line rather than counted:
`validator.go`, `caching_resolver.go`, `query_logging_resolver.go`, `models.go`,
`blocking_resolver.go` and `metrics_resolver.go`. None of the deltas touches a fix's logic. The two
that come closest are settled by measurement rather than by reading — `06555e0`/`77b0fe7` in
`metrics_resolver.go` (§5) and `316b073`/`e0ea9b3` in `blocking_resolver.go` (§5, §3).

`server/server.go` is the largest delta and the one most likely to strand a fix in dead code, so
its two checklist-relevant call sites were diffed directly: the `newClientQuery` /
`normalizeResponse` pair that `a42d656` and `db8d889` live behind is reached from the same place as
upstream (the surrounding 60 lines differ only in the chain hot-swap line), and
`createQueryResolver` is position-for-position identical apart from the dropped `StatsResolver`
(§7).

Upstream's own tests came through as well: of the 83 test files those commits touch, 73 are
byte-identical, none were deleted, and in the 10 that carry fork edits every spec the commit added
is still present — checked by name, including the `refused` block-type table, the 9 DO-bit
normalization specs, the bounded-`ReasonLabel` specs and the `queryLog type is none` skip spec.

`go test ./...` minus e2e: all packages pass. e2e still needs a container runtime, and there is
none on this host (`docker`, `podman`, `nerdctl` all absent, no `/var/run/docker.sock`) — see §3.4a
and GRA-634.

## 2. One gap found, and closed

`769d908` (the `refused` block type) was **present but unreachable**. The resolver had
`refusedBlockHandler`, but the fork's configuration surface could not select it:
`configstore.BuildBlockingConfig` *replaces* `blocking.blockType` with the store's value, so YAML
cannot reach it, and the store's only writer —
`PUT /api/config/block-settings` — rejected anything but `ZEROIP`, `NXDOMAIN` or an IP literal:

```
{"message":"block_type must be ZEROIP, NXDOMAIN, or a valid IP address"}  400
```

This is the shape of failure the checklist exists to catch: the upstream code merged cleanly, its
unit tests pass, and the feature is still dead in this fork. Fixed on this branch —
`validateBlockSettings` accepts `REFUSED`, the Block Settings page offers it, and the handbook
documents it. `createBlockHandler` already lowercases, so no resolver change was needed. Verified
by probe afterwards (§4).

Reviewing that fix turned up the same defect one line away. `createBlockHandler` also accepts a
**comma-separated list** of destination addresses, and `docs/configuration.md` advertises the
"one IPv4 plus one IPv6, to cover every query type" form — but the validator ran a bare
`net.ParseIP` on the whole string, so that form was unreachable too. It now accepts a list where
every member parses, and rejects one where any member does not.

Both gaps share one root cause worth naming for the next sync: the set of block types the API
accepts and the set `resolver.createBlockHandler` implements are two independent lists that nothing
forces to agree. They are now coupled only by a comment at each end, plus a `configstore` spec
asserting a stored `REFUSED` survives `BuildBlockingConfig` — the seam that was silently discarding
it.

## 3. Security and correctness

| Item | Evidence | Observation |
| --- | --- | --- |
| `2496d12` DNSSEC bypass & cache-scope pollution (GHSA-x845-2f78-7v36) | probe | `dnssec-failed.org A` with DO → **SERVFAIL**, `EDE 9 (DNSKEY Missing): no SEP matching the DS found for dnssec-failed.org.` A bypass would have returned the answer. `cloudflare.com A` with DO → NOERROR, `ad` flag, RRSIG in the answer |
| `a191ad2` Indeterminate, not Bogus, for an unreachable chain | probe | Mock upstream that signs every answer with an RRSIG whose signer's DNSKEY always SERVFAILs → **NOERROR, answer returned, `ad` clear**. Pre-fix this funnels to Bogus/SERVFAIL. Contrast the genuinely bogus zone above, and an *unsigned* answer whose DS lookup fails, which stays Bogus |
| `d3a1fe5` don't cache transient Indeterminate results | probe | Same mock, same question twice: the DNSKEY/DS attempts at the mock went 2 → 4, so validation was re-attempted rather than served from the validation cache |
| `fc353a0` only validate public-upstream answers | probe | `printer.lan A` (custom DNS) with DO → NOERROR, `ad` clear, no SERVFAIL — a local answer is never dragged through the chain of trust |
| `a42d656` no DNSSEC records for a client with DO clear | probe | `cloudflare.com A` `+dnssec` → 3 answers incl. RRSIG, `ad` set. Same name `+noedns` → 2 answers, **no RRSIG, ADDITIONAL: 0** (no OPT back to a client that sent none) |
| `2ffe18a` RFC 4034 canonical name ordering for NSEC coverage | probe + code path | `nonexistent-gra636.nlnetlabs.nl`, `zzz.aaa.nlnetlabs.nl`, `nonexistent-gra636.isc.org` and `zz.a.ripe.net` with DO → **NXDOMAIN**, NSEC + `RRSIG NSEC` in the authority, `ad` set. That rcode matters: `validateNSECDenialOfExistence` only routes to `validateNSECNXDOMAIN` — the caller of the fixed `nsecCoversName` — on `RcodeNameError`, so Cloudflare-style NSEC black lies (NOERROR/NODATA) never reach it. Multi-label qnames are the shape where byte and label ordering diverge, but which NSEC pair a zone hands back is not ours to choose, so the comparison itself rests on `nsec_test.go` — byte-identical and passing, with explicit specs for canonical ordering, differing label counts and underscore-prefixed names |
| `e0ea9b3` recursive RLock in blocking group resolution | code path | Settled in GRA-632/634: our `isGroupDisabled` helper held the lock and was removed for upstream's snapshot-and-release. Re-read here: `groupsToCheckForClient` releases `status.lock` before calling `collectGroupsForClient`. `blocking_resolver_concurrency_test.go` byte-identical and passing |

## 4. Protocol and blocking

| Item | Evidence | Observation |
| --- | --- | --- |
| `c46ed64` DoH stale pooled-connection retry | code path | **Not probeable here.** The retry fires only when the connection pool hands back a connection the server has already closed, which means driving the server's close timing between two requests — upstream's `mock_doh_upstream_server_test.go` exists precisely because that cannot be arranged against a real upstream. (The TLS side is not the obstacle: Go honours `SSL_CERT_FILE`, so a local DoH server with a generated CA is reachable.) DoH itself is verified live — 12 queries answered by `https://cloudflare-dns.com/dns-query`. `resolver/upstream_resolver.go` and `util/http.go` byte-identical; that mock plus `upstream_resolver_test.go` and `util/http_test.go` byte-identical and passing |
| `db8d889` compress responses larger than 512 bytes | probe | 40 A records for one name: **received 692 bytes**, repacked uncompressed 972. An 83-byte answer is received at 83 bytes even though compressing would save 11 — exactly the `res.Len() > dns.MinMsgSize` condition, not blanket compression |
| `1d450af` case-insensitive custom-DNS PTR | probe | `5.178.168.192.IN-ADDR.ARPA. PTR` → `printer.lan.` (lower-case form answers identically) |
| `91a8f44` bootstrap: fall back to other resolved addresses on dial failure | probe | `Bootstrap.dialContext` is also the dialer behind `NewHTTPTransport`, so a **plain-HTTP blocklist download** reaches it with no TLS involved. A bootstrap stub answered `lists.test A` with `127.0.0.99` (nothing listening) followed by `127.0.0.1` (a local list server); `dialContext` shuffles, so across 11 list imports the dead address came first 6 times. Trace logging shows each of those dialing `127.0.0.99` then `127.0.0.1`, and **all 11 imports succeeded, 0 failed** — pre-fix the 6 would have failed. The downloaded rule is in effect: `BLOCKED (bootlist: blocked-via-bootstrap.example.org)` |
| `e2b40db` original name to the next resolver for rewritten queries | probe | `customDNS.rewrite: {test-alias: com}`, mapping has nothing for `example.com`: `example.test-alias A` → **NXDOMAIN**, while `example.com A` resolves. Pre-fix the rewritten name leaked downstream and the client got `example.com`'s addresses |
| `dcdd952` fallbackUpstream for rewritten queries | probe | `customDNS.rewrite: {home: lan}` + mapping `printer.lan A`. `printer.home TXT` (mapping matches the name, not the type): `fallbackUpstream: false` → NOERROR + SOA; `true` → the query goes upstream **under the original name** and comes back NXDOMAIN. Mapping hits still answer locally in both cases |
| `769d908` `refused` block type | probe | After the §2 fix: `ads.example.org` answers **REFUSED for A, AAAA, TXT, MX and HTTPS**; an unblocked name still resolves NOERROR |
| `4b524e8` ECS `useAsClient` above cache and client-name lookup | probe | Client group `ecsgroup` keyed on `203.0.113.0/24`, no group for `127.0.0.1`. Query from 127.0.0.1: not blocked. Same query with `+subnet=203.0.113.9/32`: **blocked** (`BLOCKED (_d_1: ecs-blocked.example.org)`), and the metric label is `client="203.0.113.9"` — so the ECS identity reached blocking *and* the client-name/metrics path. Repeating the non-ECS query afterwards still returns the real (empty) upstream answer: no cache-scope leak |
| `c851293` matched rule in the block reason | probe | EDE extra text: `BLOCKED (_d_3: ads.example.org)` for an exact entry, `BLOCKED (_d_4: /.*\.tracker-example\.org/)` for a regex, `BLOCKED (adlist: blocked-by-list.example.org)` for a downloaded list |
| `99ae703` filter `ipv6hint` when AAAA is filtered | probe | With `filtering.queryTypes: [AAAA]`, `crypto.cloudflare.com HTTPS` returns `alpn`, `ipv4hint` and `ech` but **no `ipv6hint`**; the same query on an instance without filtering keeps the hint. Its AAAA query is empty on the filtered instance |

## 5. Metrics and performance

Three of the four correctness-shaped items were probed — `77b0fe7` rests on code path, since it
added no benchmark of its own. The five allocation-shaped ones were measured against upstream
`2bb9b70` in a worktree, `-count 3`, same host, same Go.

| Item | Evidence | Observation |
| --- | --- | --- |
| `7dd039c` `client_response_total` | probe | `blockasaurus_client_response_total{client="127.0.0.1",response_type="BLOCKED"}` and siblings for `CUSTOMDNS`/`RESOLVED`. Renamed to the fork prefix, and `metrics/metrics_test.go` gates that |
| `06555e0` bounded reason label for blocked responses | probe | Same query, two surfaces: metric `reason="BLOCKED (_d_3)"` (group only) while EDE and the query log carry `BLOCKED (_d_3: ads.example.org)`. The rule never reaches the label, so a large deny list cannot blow up cardinality |
| `77b0fe7` no per-query label-map allocations | code path | `metrics_resolver.go` uses `WithLabelValues` on every hot-path metric; no `prometheus.Labels{}` literal survives in `Resolve`. Note the fork calls `recordStats` *above* the `cfg.Enable` gate (by design, §4b) — that is fork cost for the dashboard collector, unrelated to the upstream fix |
| `223df0c` skip LogEntry build when the query log is off or ignored | probe + code path | `Resolve` returns early on `QueryLogTypeNone`, and the ignore path only builds an entry when debug logging would emit it. The ignore path is probed live under `b82199b` in §6 |
| `b73422e` allocation-free `ParallelBestResolver` selection | bench | `BenchmarkParallelBestResolverSelection` — **0 B/op, 0 allocs/op** in all four sub-cases, identical to upstream |
| `316b073` pre-classified client groups | bench | `BenchmarkBlockingGroupsToCheck{LiteralName,GlobName}` — 200 B/op, 5 allocs/op, identical to upstream. This is the benchmark that would have caught the fork's `clientMatch` attribution adding an allocation; it does not |
| `6da7ce1` lock-free grouped cache, cheapest-first lookup | bench | `BenchmarkGroupedCacheMiss` 0 allocs/op; `stringcache` files byte-identical. Exercised end to end by every blocking probe in §4 |
| `87be127` sharded result cache | bench | `BenchmarkCachingResolverResolve` 1679 B/op, 23 allocs/op, identical to upstream; `cache/shards.go` byte-identical |
| `302ca65` per-request logger allocations | bench | `BenchmarkChainLoggingPlumbing` 10168 B/op / 109 allocs/op and `BenchmarkDebugFieldBuild_Avoided` 120 B/op / 7 allocs/op, identical to upstream |

## 6. Features

§6 asks only that these *merged*; enablement is D5. They were nonetheless driven live, because
"merged" in this fork also has to mean "reachable" — the store replaces three config sections, and
`769d908` in §2 shows what that can cost.

| Item | Evidence | Observation |
| --- | --- | --- |
| `c32863d` DoQ upstream | probe | Store URL `quic://dns.adguard.com` → `RESOLVED (quic:dns.adguard.com)`. The REST API validates upstream URLs with `config.ParseUpstream`, so every scheme upstream supports is reachable through the store |
| `842dda9` DoH over HTTP/3 | probe | `http3.enable: true` + `ports.https`: `curl --http3-only` DoH GET on the UDP mirror → HTTP/3, 200, 83-byte DNS answer. Self-signed certificate generated by the server |
| `1b8e08a` DoT pooling | probe | `tcp-tls:1.1.1.1:853` answered five consecutive queries |
| `bee2d8b` UDP-first plain DNS + EDNS0 buffer floor | probe | A **UDP-only** mock upstream is reachable at all, so the plain-DNS client is UDP-first. The mock reports `advertised_udpsize=1232` even for a client that sent no OPT and for one that asked for 512 — and that client gets `ADDITIONAL: 0` back |
| `e6b41db` per-client rate limiting | probe | `rate: 2, burst: 2`: 5 of 15 queries dropped, `blockasaurus_rate_limit_drops_total{protocol="UDP"} 5`, `rate_limit_active_buckets 1` |
| `0b70e5c` rebinding protection | probe | `127.0.0.1.nip.io` and `10.0.0.1.nip.io` → `REBIND (rebinding protection)`; `93.184.215.14.nip.io` passes through |
| `7abca44` PROXY protocol | probe | `ports.proxyProtocol: [dns]`: a plain TCP DNS query gets **no response**; the same query behind `PROXY TCP4 203.0.113.7 …` is answered, and the query log attributes it to `client_ip=203.0.113.7` |
| `e43b5e5` SQLite query log | probe | `queryLog.type: sqlite` → rows in `log_entries` (with the fork's `client_group` column) |
| `e9deb53` dnstap query log | probe | `queryLog.type: dnstap`, `target: unix:…`: 3 queries → **3 dnstap frames, 561 bytes** on the socket |
| `b82199b` query-log domain ignore | probe | `ignore.domains: [ignored.example.org]`: that name is absent from the sqlite log while the two queries around it are present |
| `22b0bdd` schedule-based blocking | probe | `listSchedules: {_d_3: [inactive]}` with a window that is not now: `ads.example.org` stops being blocked while unscheduled `_d_4` still blocks. Keyed on the fork's store-managed group names, since `schedules`/`listSchedules` are the part of `blocking:` the store does *not* replace |
| `e7958e0` on-disk list download cache | probe | `downloads.cachePath` set: a cache file appears after the first load, and `POST /api/lists/refresh` issues a conditional request the origin answers **304** |
| `c44017a` sensitive config values from files | probe | `queryLog.target: file:///…/qlog-target.txt` → the server logs the path read *from that file* as its target |
| `7c6da15` config-folder structural merge | probe | `--config <dir>` with `00_base.yaml` + `10_extra.yaml`: `ports.dns` from the first and `ports.dohPath` from the second both apply, so the merge is structural rather than whole-key. `validate` logs the merge order |
| `fdcf351` client names from hosts file and custom DNS | probe | A custom-DNS `A` record for `127.0.0.1` makes the query log report `client_name=probehost.lan` instead of the bare IP |
| `f457ec9` `resolvFile` bootstrap | probe | `bootstrapDns: [{resolvFile: …}]` → "loaded 2 bootstrap nameserver(s) from resolvFile", and a hostname-only DoH upstream resolves through it |
| `0de3fac` `resolver.arpa` / DDR per RFC 9462 | probe | `_dns.resolver.arpa SVCB` and `resolver.arpa A` → NOERROR/NODATA answered locally with `EDE 17 (Filtered): Special-Use Domain Name`, i.e. not forwarded, so a stub cannot be upgraded past blockasaurus |
| `4cf62ce` healthcheck follows `ports.dns` | probe | `blockasaurus healthcheck --config …` → `OK` against `127.0.0.1:55401`; the default port 53 has nothing listening |

## 7. Two things worth recording

**Not adopted, deliberately.** Upstream's `resolver.NewStatsResolver(ctx, cfg.Statistics)` is the
one chain member this fork drops: `pkg/statscollector` persists the same statistics instead, fed
from `metrics_resolver.go` (§4b). The rest of `createQueryResolver` is position-for-position
identical to `2bb9b70`, including the ECS/client-name/rate-limit ordering `4b524e8` depends on.
D7 (`GET /docs/config.schema.json`) and GRA-647 (`/debug/*` without a session) were left alone as
the issue directs.

**An upstream nit, not port damage.** For a rewritten custom-DNS query that matches the name but
not the type, the NODATA authority SOA is emitted under the *rewritten* owner name while the answer
section is restored to the client's name:

```
$ dig printer.home TXT          # customDNS.rewrite: {home: lan}, mapping: printer.lan A
;; ->>HEADER<<- status: NOERROR
printer.lan.  3600  IN  SOA  blocky.local. hostmaster.blocky.local. …
```

`custom_dns_resolver.go` and `rewrite_helper.go` are byte-identical to upstream, so this is
upstream behavior that arrived with `e2b40db`; the rewrite-back path only restores the answer
section. Harmless (the SOA is advisory) but worth an upstream issue.

## 8. Reproducing this

Everything ran on one host with the binary built from this tree — no container runtime. Eight
instances, each with its own YAML and SQLite store, seeded through the REST API and then
**restarted** (the store repairs the `default` client group at open, so the config a fresh boot
derives is not the one that was live before). Ports 554xx.

| Instance | YAML that matters | Used for |
| --- | --- | --- |
| A | `dnssec.validate`, `ede.enable`, `prometheus.enable`, sqlite query log + `ignore.domains`, `blocking.schedules`/`listSchedules`, `blockType: REFUSED` via the API | §3 DNSSEC set, `db8d889`, `1d450af`, `c851293`, `06555e0`, `7dd039c`, `769d908`, `22b0bdd`, `e43b5e5`, `b82199b`, `c44017a`, `fdcf351`, `0de3fac`, `4cf62ce` |
| B | `filtering.queryTypes: [AAAA]` | `99ae703` |
| C | `customDNS.rewrite`, `fallbackUpstream` toggled | `e2b40db`, `dcdd952` |
| D | `ecs.useAsClient: true`; upstreams swapped to DoH / DoQ / DoT | `4b524e8`, `c32863d`, `1b8e08a` |
| F | `rebindingProtection`, `downloads.cachePath`, `rateLimit`; blocklist source served from a local HTTP server | `0b70e5c`, `e7958e0`, `e6b41db` |
| G | `ports.https` + `http3.enable`, then `ports.proxyProtocol: [dns]`, then dnstap query log | `842dda9`, `7abca44`, `e9deb53` |
| H | `--config <dir>` with two fragments, `bootstrapDns.resolvFile` | `7c6da15`, `f457ec9`, `bee2d8b` |
| I | `dnssec.validate` against the unreachable-chain mock | `a191ad2`, `d3a1fe5` |
| J | `bootstrapDns` pointed at a stub that resolves the list host to a dead address and a live one, `log.level: trace` | `91a8f44` |

Four throwaway helpers, none committed (they are twenty lines each and the fork does not need more
surface):

- **raw-wire probe** — sends one query over a plain UDP socket, keeps the received byte count, then
  re-packs the unpacked message with `Compress` false and true. `received < repacked_uncompressed`
  is the only honest way to say "the server compressed this". `tools/dnsreplay` deliberately elides
  sizes, so it cannot answer this.
- **UDP-only stub** — `miekg/dns` server bound to `udp` only; answers a fixed A record and prints
  the transport and the advertised EDNS0 buffer size of each query. Listening on UDP alone is what
  makes "UDP-first" falsifiable.
- **unreachable-chain stub** — same, on UDP and TCP: SERVFAIL for every `DS`/`DNSKEY` (counting
  them), and for `A` a record plus an RRSIG whose `SignerName` is a zone the validator can
  therefore never key. That pair of behaviors is what separates Indeterminate from Bogus.
- **dnstap receiver** — `dnstap.NewFrameStreamSockInputFromPath` on a unix socket, counting frames.
  Use the library; a hand-rolled FrameStreams handshake fails with `decoding error`.
- **two-address bootstrap stub** — answers one name with a dead loopback address followed by a live
  one. `Bootstrap.dialContext` shuffles, so read the `TRACE bootstrap: dialing … ip=` lines rather
  than inferring anything from a single success.

`tools/dnsreplay` was *not* rebuilt or re-run: its matrix answers "did the merge change our
answers", which Phase 7 already settled. This phase asks a different question about 44 specific
commits, and every probe above is shaped to a single one of them.

## 9. Gates re-run

| Gate | Result |
| --- | --- |
| `go test ./...` minus e2e | all packages pass |
| `TestAPIContract`, `TestAPISpecContract` | pass — unchanged by this work |
| `make check-fork-additions` | 156/156 present — the manifest gained this document |
| `make check-fork-additions-sync` | in sync with `upstream/main` |
| `web/ui` build | succeeds; the Block Settings page carries the new option |
| e2e suite | still not run anywhere — no container runtime on this host |
| `golangci-lint` at the fork's v2.12.2 ruleset | **not run** — the binary on this host is v1.62.2, which refuses a `version: "2"` config and a go1.26 target. `gofmt -l` and `go vet` are clean on the changed packages |
