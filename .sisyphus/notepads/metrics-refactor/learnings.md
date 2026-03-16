# Learnings - Metrics Refactor

## Conventions & Patterns

(To be populated as tasks complete)

### L1.1: PostStarter Interface Implementation
- Interface added to `resolver/resolver.go` at line 106-116 (after NamedResolver)
- Method signature: `PostStart(ctx context.Context) error`
- Interface includes comprehensive godoc (6 lines) explaining:
  - Purpose: initialization requiring operational DNS server
  - When called: after all DNS listeners are up
  - Use case example: BlockingResolver FQDN IP cache initialization
- Code style: follows existing interface patterns (NamedResolver, Resolver, etc.)
- Indentation: tabs (consistent with codebase)
- Verification: `make lint` (0 issues), `make build` (successful), lsp_diagnostics (no errors)
- Key insight: This interface replaces ApplicationStarted event pattern for post-startup initialization

### L1.2: PostStart Method on BlockingResolver
- Implementation location: `resolver/blocking_resolver.go` lines 625-644
- Method signature: `func (r *BlockingResolver) PostStart(ctx context.Context) error`
- Key pattern used: `ctx, logger := r.log(ctx)` for logging (consistent with other methods in file)
- Debug logging:
  - Before: "initializing FQDN IP cache"
  - After: "FQDN IP cache initialized with %d entries" (Debugf format)
- FQDN counting logic:
  - Uses `maps.Keys(r.clientGroupsBlock)` to get all client identifiers
  - Iterates checking `isFQDN(id)` helper to count FQDNs
  - Helper already exists at line 656: `func isFQDN(in string) bool`
- Initialization: calls existing `r.initFQDNIPCache(ctx)` without modification
- Error handling: returns nil (no errors expected per spec)
- Code style: blank line before final return (required by nlreturn linter)
- Verification: `make lint` (0 issues), `make build` (successful)
- Key insight: PostStart enables FQDN cache initialization after DNS server is operational

## L1.3: PostStart Hook Calling Pattern

**Implementation**: Added PostStart hook calling in `server.Start()` method.

**Code Pattern** (lines 425-434 in server/server.go):
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

**Key Points**:
1. Inserted AFTER DNS listeners are up (line 423) but BEFORE registerPrintConfigurationTrigger (now line 436)
2. Uses `resolver.ForEach()` to iterate the chain - it properly handles chained resolvers
3. Type-asserts each resolver to `resolver.PostStarter` interface
4. Calls `PostStart(ctx)` on implementing resolvers
5. Logs warnings (not errors) if PostStart fails - does NOT fail server startup
6. Debug level log before iteration, Warning level on failures
7. Context is passed through so PostStart can use same context as server startup

**Why This Timing**:
- PostStart needs DNS listeners already running because resolvers may perform DNS lookups during initialization
- BlockingResolver.PostStart() initializes FQDN IP cache by querying custom domains through upstream resolvers
- Those queries require operational upstream DNS to be available

**Related Implementations**:
- BlockingResolver.PostStart() exists at blocking_resolver.go lines 625-644
- PostStarter interface at resolver/resolver.go lines 106-116
- ForEach function at resolver/resolver.go lines 156-170

**Verification**: make lint ✓, make build ✓, lsp_diagnostics clean ✓

### L1.4: Remove ApplicationStarted Event Subscription from BlockingResolver
- **Location**: `resolver/blocking_resolver.go` lines 168-173 (DELETED)
- **Code removed**:
  ```go
  err = evt.Bus().SubscribeOnce(evt.ApplicationStarted, func(_ ...string) {
      go res.initFQDNIPCache(ctx)
  })
  if err != nil {
      return nil, fmt.Errorf("failed to subscribe to ApplicationStarted event: %w", err)
  }
  ```
- **Import handling**: 
  - `evt` import at line 23 was KEPT (not removed)
  - Reason: `evt` is still used by BlockingResolver in two places:
    - Line 243: `evt.Bus().Publish(evt.BlockingEnabledEvent, true)` (in enableBlocking method)
    - Line 284: `evt.Bus().Publish(evt.BlockingEnabledEvent, false)` (in disableBlocking method)
- **Functional equivalence**:
  - FQDN IP cache initialization previously triggered by ApplicationStarted event
  - Now triggered by PostStart() hook called by server.Start() after DNS listeners are up
  - Same initialization logic (`r.initFQDNIPCache(ctx)`) still exists and is called by PostStart
- **Why removal works**:
  - L1.3 established that server.Start() calls PostStart on all resolvers
  - BlockingResolver.PostStart (L1.2) calls initFQDNIPCache internally
  - Event-based approach is now redundant and superseded by interface-based lifecycle
- **Verification**: 
  - `make lint` ✓ (0 issues)
  - `make build` ✓ (successful)
  - grep -n "ApplicationStarted" blocking_resolver.go ✓ (no matches - subscription completely removed)
- **Key insight**: Transition from event-based to interface-based lifecycle is working correctly; ApplicationStarted event is no longer needed for BlockingResolver initialization

## L1.5: ApplicationStarted Event Removal

**Completed**: Removed ApplicationStarted event publication from cmd/serve.go

**Details**:
- Removed line 89: `evt.Bus().Publish(evt.ApplicationStarted, util.Version, util.BuildTime)`
- Removed unused import: `"github.com/0xERR0R/blocky/evt"` from line 12
- Verification:
  - No remaining evt references in serve.go (grep confirmed)
  - `make lint` passes (0 issues)
  - `make build` succeeds
- Confirmed: PostStarter interface pattern has fully replaced event-based lifecycle
