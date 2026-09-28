# Pre-merge behavioral baseline — v0.34.38

This is the "before" half of Phase 0 (see `docs/UPSTREAM_SYNC.md` §5). It exists so that
after the upstream merge, "did we regress?" is answered by diffing against a recorded
result rather than by remembering what used to pass.

| | |
| --- | --- |
| Rollback tag | `pre-upstream-sync-v0.34.38` |
| Commit | `7e0a40c66fcf1e9581355046eed24b8d1651f91f` (2026-09-21) |
| `VERSION` | 0.34.38 |
| Go | go1.26.4 linux/amd64 |
| Measured | 2026-09-23 |

Re-measure after the merge with the same command and diff against the table below:

```bash
go test ./... 2>&1 | grep -E '^(ok|FAIL|---|\?)'
```

## `go test ./...`

Every package with tests passes except `e2e`, which could not run here — see below.

| Package | Result |
| --- | --- |
| `api` | ok |
| `api/configapi` | ok |
| `auth` | ok |
| `cache/prefetching` | ok |
| `cache/stringcache` | ok |
| `cmd` | ok |
| `config` | ok |
| `configstore` | ok |
| `e2e` | **not run** — see below |
| `lists` | ok |
| `lists/parsers` | ok |
| `logstream` | ok |
| `metrics` | ok |
| `pkg/advertise` | ok |
| `pkg/arp` | ok |
| `pkg/statscollector` | ok |
| `querylog` | ok |
| `redis` | ok |
| `resolver` | ok |
| `resolver/dnssec` | ok |
| `server` | ok |
| `trie` | ok |
| `util` | ok |

No test files: root package, `auth/authmodels`, `cache`, `config/migration`, `docs`, `evt`,
`helpertest`, `log`, `model`, `pkg/winservice`, `web`.

`server` includes the two new guardrail tests (`TestAPIContract`, `TestAPISpecContract`).

## e2e suite — NOT a recorded baseline

`go test ./e2e` failed all 75 specs in `BeforeEach` with `rootless Docker not found`
(`testcontainers-go/internal/core/docker_host.go:91`). The suite needs a Docker daemon;
the environment this baseline was captured in has none.

**This is an unmeasured baseline, not a passing one.** Treat it as an open item: run
`make e2e-test` on a machine with Docker before starting Phase 2, and record the result
here. Until that happens, the merge has no e2e "before" to be compared against, and the
Phase 6 gate cannot honestly be called met on the strength of this document.

## Guardrails

Green at this commit:

```bash
go test ./server -run 'TestAPIContract|TestAPISpecContract'   # both pass
make check-fork-additions                                     # all 149 files present
make check-fork-additions-sync                                # manifest in sync with upstream/main
```

`check-fork-additions-sync` was verified against a real `upstream/main` fetch
(`2bb9b70f6ddcd5a35d9c57c175690fd886aa3e72`), not just the skip path.

## Not captured here — closed 2026-09-28

Phase 0 in the plan also calls for a captured set of DNS answers
(blocked/allowed/custom/conditional/DNSSEC/EDNS0) and dashboard screenshots, which Phase 7
replays. Neither was captured at the time, so there was no recorded "before" to diff against.

**Phase 7 closed this without them.** Rather than replay against a missing artifact, it built and
ran *both* trees side by side — this tag and post-merge `main` — with byte-identical
config-store contents, and diffed the answers directly. Neither needs Docker: the binary runs
fine on the host, and the browser pass used headless Chromium. Results, including every
explained delta, are in `behavioral-replay-2026-09.md`.

The capture is reproducible for the next sync: `go run ./tools/dnsreplay <host:port>`.
