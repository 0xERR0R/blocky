// Copyright 2026 Chris Snell
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/0xERR0R/blocky/auth"
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/configstore"
	"github.com/0xERR0R/blocky/logstream"
	"github.com/0xERR0R/blocky/pkg/statscollector"

	"github.com/go-chi/chi/v5"
)

// updateAPIContract regenerates the golden file instead of asserting against
// it. Changing the golden is changing the public API contract, so it is a
// deliberate, reviewable act:
//
//	go test ./server -run TestAPIContract -update-api-contract
var updateAPIContract = flag.Bool("update-api-contract", false,
	"rewrite the API contract golden file")

const apiContractGolden = "testdata/api_contract.golden"

// TestAPIContract locks the HTTP surface of the server.
//
// It builds the real production router — the same createHTTPRouter the server
// uses, not a replica — walks every registered route, and records for each one
// the method, the path pattern, and the middleware chain guarding it.
//
// This exists because Blockasaurus is a fork of blocky that is periodically
// merged with upstream (see docs/UPSTREAM_SYNC.md). A merge can silently drop
// one of our endpoints, strip RequireAuth from a route by resolving a
// conflicted Group block toward upstream's brace layout, or import an upstream
// route that collides with ours. None of those show up as a compile error and
// most do not fail an existing test. They do fail here.
//
// What this test does NOT cover, so nobody trusts it further than it reaches:
//
//   - Request and response body shape. TestAPISpecContract below covers the
//     OpenAPI operation set; the schemas behind those operations are not
//     locked by anything.
//   - Fork edits to upstream files generally. See .fork-additions and
//     docs/UPSTREAM_SYNC.md §7.
//   - Middleware behavior. Only the identity and order of the chain is
//     recorded, not what it does.
//
// A diff here is not automatically a bug — but it is always a change to the
// contract the web UI and any API consumer depend on, and it must be
// acknowledged rather than absorbed.
func TestAPIContract(t *testing.T) {
	router := buildContractRouter(t)

	routes, err := walkRoutes(router)
	if err != nil {
		t.Fatalf("walk routes: %v", err)
	}

	assertGolden(t, apiContractGolden, strings.Join(routes, "\n")+"\n",
		"HTTP API contract changed",
		"go test ./server -run TestAPIContract -update-api-contract")
}

// buildContractRouter constructs the production router with every optional
// subsystem present, so no route is conditionally skipped. A nil config store
// or nil broadcaster would silently drop whole route groups and make the
// golden weaker than the thing it is guarding.
//
// The result is wrapped in withCommonMiddleware, because that is how every
// router actually reaches the network: newHTTPServer applies it to whatever it
// is given (server/http.go). Walking createHTTPRouter's output directly would
// leave the outermost layer — secureHeadersMiddleware and the fork's
// same-origin CORS policy — outside the contract, and server/http.go is an
// upstream file carrying fork edits, exactly the category most at risk in a
// merge.
func buildContractRouter(t *testing.T) *chi.Mux {
	t.Helper()

	store, err := configstore.Open(filepath.Join(t.TempDir(), "contract.db"))
	if err != nil {
		t.Fatalf("open configstore: %v", err)
	}

	t.Cleanup(func() { _ = store.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	broadcaster := logstream.NewBroadcaster(ctx, 1)
	t.Cleanup(broadcaster.Shutdown)

	collector := statscollector.New()
	t.Cleanup(collector.Close)

	// Start from real defaults rather than a zero Config so that any route
	// pattern derived from a `default:` tag — notably ports.dohPath — is
	// pinned by the golden too.
	defaulted, err := config.WithDefaults[config.Config]()
	if err != nil {
		t.Fatalf("config defaults: %v", err)
	}

	cfg := &defaulted
	cfg.Prometheus.Enable = true

	// metrics.Start mutates the package-global prometheus registry, which
	// server_endpoints_test.go deliberately avoids. We accept that here
	// because the metrics route cannot be captured without calling it, and
	// because Start ignores duplicate-registration errors.
	router := createHTTPRouter(cfg, nil, store, nil, broadcaster, collector, auth.NewWSRevoker())

	// DoH lands on this same mux whenever the admin UI is not on separate
	// listeners (see NewServer). Registration reads only cfg, so a zero
	// Server is sufficient to record the route shape.
	(&Server{}).registerDoHEndpoints(router, cfg)

	return withCommonMiddleware(router)
}

// allMethods is chi's full method set (its mALL). A route registered with
// Handle() (as opposed to Get/Post/...) is expanded by chi into one entry per
// method; we collapse those back into a single ANY line so the golden stays
// readable and a real change is not buried under ten identical rows. The
// collapse is conditional on all of those chains being identical, so it can
// never hide a per-method difference in the guards.
//
// This list must track chi's: it gained QUERY (RFC 10008) in v5.3.0, and until
// this list followed, every Handle() route lost its ANY collapse and expanded
// into one golden line per method. Adding a method here does not hide the new
// route — the ANY line covers it — so a chi bump that widens mALL is still
// visible as a contract change wherever the guards differ.
var allMethods = []string{
	"CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "QUERY", "TRACE",
}

type routeKey struct {
	pattern string
	method  string
}

// walkRoutes returns "METHOD /pattern [middleware...]" for every route in the
// tree, sorted by pattern so the golden is stable across registration-order
// changes.
//
// The middleware chain is the reason this is not just a list of paths: moving
// a route out of the authenticated group strips RequireAuth without changing
// its method or path, and that is both the likeliest and the most damaging
// regression an upstream merge can introduce here.
func walkRoutes(router *chi.Mux) ([]string, error) {
	chains := map[routeKey][]string{}
	methodsByPattern := map[string]map[string]bool{}

	walk := func(method, route string, _ http.Handler,
		middlewares ...func(http.Handler) http.Handler,
	) error {
		if methodsByPattern[route] == nil {
			methodsByPattern[route] = map[string]bool{}
		}

		methodsByPattern[route][method] = true
		chains[routeKey{route, method}] = middlewareNames(middlewares)

		return nil
	}

	if err := chi.Walk(router, walk); err != nil {
		return nil, err
	}

	patterns := make([]string, 0, len(methodsByPattern))
	for pattern := range methodsByPattern {
		patterns = append(patterns, pattern)
	}

	sort.Strings(patterns)

	// The withCommonMiddleware layer is on every route by construction, so
	// repeating it 85 times would bury the per-route guards that actually
	// differ — and "[public]" only reads as public if the common layer is not
	// in the way. Record it once, and strip it from the per-route chains.
	// Should some route ever escape that layer, the shared prefix shrinks and
	// every line changes: loud, which is the correct failure here.
	common := commonPrefix(chains)

	guards := map[routeKey]string{}
	for key, chain := range chains {
		guards[key] = formatChain(chain[len(common):])
	}

	routes := []string{
		"# Applied to every route below by withCommonMiddleware (server/http.go):",
		formatRoute("COMMON", "*", formatChain(common)),
		"",
	}

	for _, pattern := range patterns {
		methods := byPatternMethods(methodsByPattern[pattern])

		if guard, ok := uniformGuard(pattern, methods, guards); ok {
			routes = append(routes, formatRoute("ANY", pattern, guard))

			continue
		}

		for _, m := range methods {
			routes = append(routes, formatRoute(m, pattern, guards[routeKey{pattern, m}]))
		}
	}

	return routes, nil
}

// commonPrefix returns the leading middlewares shared by every route.
func commonPrefix(chains map[routeKey][]string) []string {
	var (
		prefix []string
		first  = true
	)

	for _, chain := range chains {
		if first {
			prefix = append([]string(nil), chain...)
			first = false

			continue
		}

		if len(chain) < len(prefix) {
			prefix = prefix[:len(chain)]
		}

		for i := range prefix {
			if chain[i] != prefix[i] {
				prefix = prefix[:i]

				break
			}
		}
	}

	return prefix
}

func formatRoute(method, pattern, guard string) string {
	return fmt.Sprintf("%-7s %-45s %s", method, pattern, guard)
}

// middlewareNames renders the guards on a route by function name, in order.
// Closures returned by middleware constructors resolve to stable names like
// "auth.RequireAuth.func1", which is enough to tell "authenticated" from
// "public" and to notice a guard being dropped or reordered.
func middlewareNames(middlewares []func(http.Handler) http.Handler) []string {
	names := make([]string, 0, len(middlewares))

	for _, mw := range middlewares {
		full := runtime.FuncForPC(reflect.ValueOf(mw).Pointer()).Name()
		names = append(names, middlewareName(full))
	}

	return names
}

// formatChain renders a middleware chain, naming the empty chain "[public]" so
// a route losing its guards is obvious at a glance rather than an absence.
func formatChain(names []string) string {
	if len(names) == 0 {
		return "[public]"
	}

	return "[" + strings.Join(names, " ") + "]"
}

// methodValueSuffix is what the compiler appends to a method used as a value,
// e.g. cors.(*Cors).Handler passed to Use() becomes "cors.(*Cors).Handler-fm".
const methodValueSuffix = "-fm"

// middlewareName reduces a runtime symbol like
// "github.com/0xERR0R/blocky/server.registerUIRoutes.func1.RequireAuth.2" to
// the middleware it actually is: "RequireAuth". The trailing segments are
// closure indices the compiler assigns, and the leading ones are whichever
// function happened to install the middleware — neither is part of the
// contract, and both churn on unrelated edits.
//
// Method values keep their receiver type, so the CORS handler reads as
// "Cors.Handler" rather than a bare, ambiguous "Handler".
//
// One limitation worth knowing before trusting a name: a middleware declared
// inline — Use(func(next http.Handler) http.Handler { ... }) — has no name of
// its own, so this resolves to the enclosing function that installed it. Two
// different inline middlewares in the same function are therefore
// indistinguishable here, and moving one to a differently named function
// churns the golden without changing behavior. There are none today; prefer a
// named constructor if you add one.
func middlewareName(symbol string) string {
	segments := strings.Split(symbol[strings.LastIndex(symbol, "/")+1:], ".")

	for i, v := range slices.Backward(segments) {
		seg := v
		if closureSegment(seg) {
			continue
		}

		name := strings.TrimSuffix(seg, methodValueSuffix)
		if name != seg && i > 0 {
			if recv := strings.Trim(segments[i-1], "(*)"); recv != "" {
				return recv + "." + name
			}
		}

		return name
	}

	return symbol
}

func closureSegment(seg string) bool {
	seg = strings.TrimPrefix(seg, "func")

	if seg == "" {
		return true
	}

	for _, r := range seg {
		if r < '0' || r > '9' {
			return false
		}
	}

	return true
}

func byPatternMethods(methods map[string]bool) []string {
	named := make([]string, 0, len(methods))
	for m := range methods {
		named = append(named, m)
	}

	sort.Strings(named)

	return named
}

// uniformGuard reports the single middleware chain shared by every method on a
// pattern, but only when the pattern covers chi's full method set. Anything
// less, or any disagreement between the chains, is listed per method: an ANY
// line that averaged over differing guards would hide the regression this test
// exists to catch.
func uniformGuard(pattern string, methods []string, guards map[routeKey]string) (string, bool) {
	if len(methods) != len(allMethods) {
		return "", false
	}

	for _, m := range allMethods {
		if _, ok := guards[routeKey{pattern, m}]; !ok {
			return "", false
		}
	}

	guard := guards[routeKey{pattern, methods[0]}]
	for _, m := range methods {
		if guards[routeKey{pattern, m}] != guard {
			return "", false
		}
	}

	return guard, true
}

// assertGolden compares got against the golden file, or rewrites it when
// -update-api-contract is set. The failure message names the added and removed
// lines rather than dumping both files, because during an upstream merge the
// question is always "what moved?", not "what does the whole surface look
// like?".
func assertGolden(t *testing.T, path, got, what, regenCmd string) {
	t.Helper()

	if *updateAPIContract {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("create testdata dir: %v", err)
		}

		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatalf("write golden: %v", err)
		}

		t.Logf("wrote %s", path)

		return
	}

	wantBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (regenerate with -update-api-contract): %v", err)
	}

	if got == string(wantBytes) {
		return
	}

	added, removed := diffLines(string(wantBytes), got)

	var b strings.Builder

	fmt.Fprintf(&b, "%s.\n\n", what)

	// A set comparison finds nothing when the lines are the same but their
	// order or the surrounding whitespace is not — CRLF normalization, an
	// editor stripping the trailing newline, a registration reshuffle. Saying
	// so beats printing an empty report: a failure with no stated cause is one
	// a reader regenerates away without looking.
	if len(added) == 0 && len(removed) == 0 {
		b.WriteString("The same lines are present, so the difference is ordering or whitespace:\n")
		fmt.Fprintf(&b, "  golden %d bytes, got %d bytes\n", len(wantBytes), len(got))

		for _, d := range firstPositionalDiff(string(wantBytes), got) {
			fmt.Fprintf(&b, "  %s\n", d)
		}

		b.WriteString("\n")
	}

	if len(removed) > 0 {
		b.WriteString("GONE (a consumer relying on these breaks):\n")

		for _, r := range removed {
			fmt.Fprintf(&b, "  - %s\n", r)
		}
	}

	if len(added) > 0 {
		b.WriteString("NEW:\n")

		for _, r := range added {
			fmt.Fprintf(&b, "  + %s\n", r)
		}
	}

	b.WriteString("\nIf this change is intended, regenerate the golden deliberately:\n")
	fmt.Fprintf(&b, "  %s\n", regenCmd)
	b.WriteString("and call out the contract change in the pull request.\n")

	t.Fatal(b.String())
}

// firstPositionalDiff names the first line that differs by position, which is
// what identifies an ordering or whitespace-only change.
func firstPositionalDiff(want, got string) []string {
	wantLines := strings.Split(want, "\n")
	gotLines := strings.Split(got, "\n")

	for i := 0; i < len(wantLines) || i < len(gotLines); i++ {
		w, g := lineAt(wantLines, i), lineAt(gotLines, i)
		if w == g {
			continue
		}

		return []string{
			fmt.Sprintf("first difference at line %d:", i+1),
			fmt.Sprintf("  golden: %q", w),
			fmt.Sprintf("  got:    %q", g),
		}
	}

	return nil
}

func lineAt(lines []string, i int) string {
	if i >= len(lines) {
		return "<end of file>"
	}

	return lines[i]
}

func diffLines(want, got string) (added, removed []string) {
	inWant := map[string]bool{}
	for l := range strings.SplitSeq(strings.TrimSpace(want), "\n") {
		inWant[l] = true
	}

	inGot := map[string]bool{}

	for l := range strings.SplitSeq(strings.TrimSpace(got), "\n") {
		inGot[l] = true

		if !inWant[l] {
			added = append(added, l)
		}
	}

	for l := range inWant {
		if !inGot[l] {
			removed = append(removed, l)
		}
	}

	sort.Strings(added)
	sort.Strings(removed)

	return added, removed
}
