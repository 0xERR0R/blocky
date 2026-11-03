package dnssec

// This file contains upstream query management and DoS protection logic.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"

	"github.com/0xERR0R/blocky/model"
	"github.com/miekg/dns"
)

// queryBudgetKey is the context key for tracking upstream query budget
type queryBudgetKey struct{}

// clientContextKey is the context key carrying the originating client's identity so
// that DNSSEC auxiliary (DS/DNSKEY) sub-queries resolve from the same upstream view
// as the user-facing answer.
type clientContextKey struct{}

// clientContext holds the originating client's identity for DNSSEC sub-queries and the
// upstream view that answers them.
type clientContext struct {
	ip       net.IP
	names    []string
	clientID string
	view     string
}

// WithClientContext returns a context carrying the originating client's identity so
// DNSSEC auxiliary queries issued during validation preserve it. view names the upstream
// group those queries reach; validation results are cached per view. Called by the DNSSEC
// resolver before validating a response.
func WithClientContext(ctx context.Context, ip net.IP, names []string, clientID, view string) context.Context {
	return context.WithValue(ctx, clientContextKey{},
		clientContext{ip: ip, names: names, clientID: clientID, view: view})
}

// clientContextFrom extracts the originating client's identity from the context.
func clientContextFrom(ctx context.Context) (clientContext, bool) {
	cc, ok := ctx.Value(clientContextKey{}).(clientContext)

	return cc, ok
}

// withQueryBudget returns a context whose upstream queries, and those of every context derived
// from it, share a budget of n queries
func withQueryBudget(ctx context.Context, n int) context.Context {
	budget := new(atomic.Int64)
	budget.Store(int64(n))

	return context.WithValue(ctx, queryBudgetKey{}, budget)
}

// consumeQueryBudget takes one query from the budget and returns error if budget is exhausted
// This provides DoS protection by limiting the number of upstream queries per validation
func (v *Validator) consumeQueryBudget(ctx context.Context) error {
	budget, ok := ctx.Value(queryBudgetKey{}).(*atomic.Int64)
	if !ok {
		// Budget not initialized - this shouldn't happen but fail safely
		return errors.New("query budget not initialized")
	}

	if budget.Add(-1) < 0 {
		return fmt.Errorf("upstream query budget exhausted (max: %d queries per validation)", v.maxUpstreamQueries)
	}

	return nil
}

// queryBudgetExhausted reports whether the budget refused a query of this validation
func queryBudgetExhausted(ctx context.Context) bool {
	budget, ok := ctx.Value(queryBudgetKey{}).(*atomic.Int64)

	return ok && budget.Load() < 0
}

// queryRecords performs a DNS query for a specific record type with DNSSEC enabled
func (v *Validator) queryRecords(ctx context.Context, domain string, qtype uint16) (*dns.Msg, error) {
	// Check query budget (DoS protection)
	if err := v.consumeQueryBudget(ctx); err != nil {
		v.logger.Warnf("Query budget exhausted while querying %s (type %d): %v", domain, qtype, err)

		return nil, err
	}

	domain = dns.Fqdn(domain)

	// Create DNS query
	msg := new(dns.Msg)
	msg.SetQuestion(domain, qtype)
	msg.SetEdns0(ednsUDPSize, true) // Set DO bit for DNSSEC
	// Set the CD (Checking Disabled) bit so a validating upstream does not pre-filter these
	// auxiliary DS/DNSKEY lookups: we must validate the RAW records ourselves. Without it an
	// upstream like 8.8.8.8 returns SERVFAIL for a bogus chain (e.g. dnssec-failed.org), which
	// we could not distinguish from an unreachable upstream - it would be served as Indeterminate
	// instead of correctly rejected as Bogus. This is what makes validation independent (#1287).
	msg.CheckingDisabled = true

	// Create model request, preserving the originating client's identity so the
	// upstream tree selects the same group/view as the user-facing answer.
	req := &model.Request{
		Req:      msg,
		Protocol: model.RequestProtocolUDP,
	}
	if cc, ok := clientContextFrom(ctx); ok {
		req.ClientIP = cc.ip
		req.ClientNames = cc.names
		req.RequestClientID = cc.clientID
	}

	// Query upstream
	response, err := v.upstream.Resolve(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("upstream query failed: %w", err)
	}

	// The upstream keeps a truncated UDP reply when its TCP retry fails. Records may be missing
	// from it, so it counts as a failed query, not as an answer without them.
	if response.Res.Truncated {
		return nil, fmt.Errorf("upstream query failed: truncated reply for %s", domain)
	}

	return response.Res, nil
}

// queryDNSKEY queries upstream for the DNSKEY RRset of a zone
// Returns the answer section (the keys and their RRSIGs) and the keys in it
func (v *Validator) queryDNSKEY(ctx context.Context, domain string) ([]dns.RR, []*dns.DNSKEY, error) {
	response, err := v.queryRecords(ctx, domain, dns.TypeDNSKEY)
	if err != nil {
		// The sub-query itself failed (timeout/unreachable upstream/budget). This is a
		// transient inability to gather validation data, NOT proof of an invalid signature,
		// so tag it errDNSKEYUnavailable: callers propagate it as Indeterminate rather than
		// Bogus (issue #2120). A response that arrives but contains no DNSKEY records falls
		// through to the genuine "no records" failure below and stays Bogus.
		return nil, nil, fmt.Errorf("%w: %w", errDNSKEYUnavailable, err)
	}

	// SERVFAIL (the upstream could not reach the zone) is the same transient failure; any other
	// answer without keys, NXDOMAIN included, is not.
	if response.Rcode == dns.RcodeServerFailure {
		return nil, nil, fmt.Errorf("%w: SERVFAIL", errDNSKEYUnavailable)
	}

	keys, err := extractTypedRecords[*dns.DNSKEY](response.Answer)
	if err != nil {
		return nil, nil, err
	}

	return response.Answer, keys, nil
}
