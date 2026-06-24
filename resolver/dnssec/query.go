package dnssec

// This file contains upstream query management and DoS protection logic.

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/0xERR0R/blocky/model"
	"github.com/miekg/dns"
)

// queryBudgetKey is the context key for tracking upstream query budget
type queryBudgetKey struct{}

// clientContextKey is the context key carrying the originating client's identity so
// that DNSSEC auxiliary (DS/DNSKEY) sub-queries resolve from the same upstream view
// as the user-facing answer.
type clientContextKey struct{}

// clientContext holds the originating client's identity for DNSSEC sub-queries.
type clientContext struct {
	ip       net.IP
	names    []string
	clientID string
}

// WithClientContext returns a context carrying the originating client's identity so
// DNSSEC auxiliary queries issued during validation preserve it. Called by the DNSSEC
// resolver before validating a response.
func WithClientContext(ctx context.Context, ip net.IP, names []string, clientID string) context.Context {
	return context.WithValue(ctx, clientContextKey{}, clientContext{ip: ip, names: names, clientID: clientID})
}

// clientContextFrom extracts the originating client's identity from the context.
func clientContextFrom(ctx context.Context) (clientContext, bool) {
	cc, ok := ctx.Value(clientContextKey{}).(clientContext)

	return cc, ok
}

// consumeQueryBudget decrements the query budget and returns error if budget is exhausted
// This provides DoS protection by limiting the number of upstream queries per validation
func (v *Validator) consumeQueryBudget(ctx context.Context) error {
	budget, ok := ctx.Value(queryBudgetKey{}).(int)
	if !ok {
		// Budget not initialized - this shouldn't happen but fail safely
		return errors.New("query budget not initialized")
	}

	if budget <= 0 {
		return fmt.Errorf("upstream query budget exhausted (max: %d queries per validation)", v.maxUpstreamQueries)
	}

	return nil
}

// decrementQueryBudget creates a new context with decremented budget
func (v *Validator) decrementQueryBudget(ctx context.Context) context.Context {
	budget, ok := ctx.Value(queryBudgetKey{}).(int)
	if !ok {
		return ctx
	}

	return context.WithValue(ctx, queryBudgetKey{}, budget-1)
}

// queryRecords performs a DNS query for a specific record type with DNSSEC enabled
// Returns (response, newContext, error) where newContext has decremented budget
func (v *Validator) queryRecords(
	ctx context.Context, domain string, qtype uint16,
) (context.Context, *dns.Msg, error) {
	// Check query budget (DoS protection)
	if err := v.consumeQueryBudget(ctx); err != nil {
		v.logger.Warnf("Query budget exhausted while querying %s (type %d): %v", domain, qtype, err)

		return ctx, nil, err
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
		return ctx, nil, fmt.Errorf("upstream query failed: %w", err)
	}

	// Decrement budget after successful query
	newCtx := v.decrementQueryBudget(ctx)

	return newCtx, response.Res, nil
}

// queryDNSKEY queries upstream for DNSKEY records
// Returns (newContext, dnskeys, error) where newContext has decremented budget
func (v *Validator) queryDNSKEY(ctx context.Context, domain string) (context.Context, []*dns.DNSKEY, error) {
	ctx, response, err := v.queryRecords(ctx, domain, dns.TypeDNSKEY)
	if err != nil {
		// The sub-query itself failed (timeout/unreachable upstream/budget). This is a
		// transient inability to gather validation data, NOT proof of an invalid signature,
		// so tag it errDNSKEYUnavailable: callers propagate it as Indeterminate rather than
		// Bogus (issue #2120). A response that arrives but contains no DNSKEY records falls
		// through to the genuine "no records" failure below and stays Bogus.
		return ctx, nil, fmt.Errorf("%w: %w", errDNSKEYUnavailable, err)
	}

	keys, err := extractTypedRecords[*dns.DNSKEY](response.Answer)

	return ctx, keys, err
}
