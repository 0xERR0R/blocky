package dnssec

// This file contains upstream query management and DoS protection logic.

import (
	"context"
	"errors"
	"fmt"

	"github.com/0xERR0R/blocky/model"
	"github.com/miekg/dns"
)

// queryBudgetKey is the context key for tracking upstream query budget
type queryBudgetKey struct{}

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

	// Create model request
	req := &model.Request{
		Req:      msg,
		Protocol: model.RequestProtocolUDP,
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
		return ctx, nil, err
	}

	keys, err := extractTypedRecords[*dns.DNSKEY](response.Answer)

	return ctx, keys, err
}
