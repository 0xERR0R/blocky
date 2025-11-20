package resolver

import (
	"context"
	"fmt"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/resolver/dnssec"
	"github.com/miekg/dns"
)

const (
	// ednsUDPSize is the EDNS0 UDP buffer size
	ednsUDPSize = 4096
)

// DNSSECResolver is responsible for DNSSEC validation of DNS responses
type DNSSECResolver struct {
	configurable[*config.DNSSEC]
	NextResolver
	typed

	validator *dnssec.Validator
}

// NewDNSSECResolver creates a new DNSSEC resolver instance
func NewDNSSECResolver(ctx context.Context, cfg config.DNSSEC, upstream Resolver) (ChainedResolver, error) {
	// Create resolver with config
	r := &DNSSECResolver{
		configurable: withConfig(&cfg),
		typed:        withType("dnssec"),
	}

	// Only initialize validator if DNSSEC is enabled
	if cfg.IsEnabled() {
		// Load trust anchors
		trustAnchors, err := dnssec.NewTrustAnchorStore(cfg.TrustAnchors)
		if err != nil {
			return nil, fmt.Errorf("failed to load trust anchors: %w", err)
		}

		// Create logger
		_, logger := r.log(ctx)

		// Create validator with upstream resolver and config values
		r.validator = dnssec.NewValidator(
			ctx,
			trustAnchors,
			logger,
			upstream,
			cfg.CacheExpirationHours,
			cfg.MaxChainDepth,
			cfg.MaxNSEC3Iterations,
			cfg.MaxUpstreamQueries,
			cfg.ClockSkewToleranceSec,
		)

		logger.Infof("DNSSEC resolver initialized with %d root trust anchor(s)",
			len(trustAnchors.GetRootTrustAnchors()))
	}

	return r, nil
}

// Resolve validates DNSSEC signatures if validation is enabled
func (r *DNSSECResolver) Resolve(ctx context.Context, request *model.Request) (*model.Response, error) {
	ctx, logger := r.log(ctx)

	// If DNSSEC validation is enabled, set the DO (DNSSEC OK) bit
	if r.cfg.Validate {
		// Check if EDNS0 is already present in the request
		if opt := request.Req.IsEdns0(); opt != nil {
			// EDNS0 already exists - just set the DO bit
			opt.SetDo(true)
			// Ensure buffer size is adequate for DNSSEC responses
			if opt.UDPSize() < ednsUDPSize {
				opt.SetUDPSize(ednsUDPSize)
			}
			logger.Debugf("DNSSEC DO bit set for query (existing EDNS0): %s", request.Req.Question[0].Name)
		} else {
			// No EDNS0 present - add it with DO bit
			request.Req.SetEdns0(ednsUDPSize, true)
			logger.Debugf("DNSSEC DO bit set for query (new EDNS0): %s", request.Req.Question[0].Name)
		}
	}

	// Get response from next resolver (upstream)
	response, err := r.next.Resolve(ctx, request)
	if err != nil {
		return nil, err
	}

	// Validate DNSSEC if enabled and validator is available
	if r.cfg.Validate && r.validator != nil && len(request.Req.Question) > 0 {
		result := r.validator.ValidateResponse(ctx, response.Res, request.Req.Question[0])

		logger.Debugf("DNSSEC validation result for %s: %s",
			request.Req.Question[0].Name, result.String())

		switch result {
		case dnssec.ValidationResultBogus:
			// Invalid DNSSEC - return SERVFAIL
			logger.Warnf("DNSSEC validation failed for %s - returning SERVFAIL",
				request.Req.Question[0].Name)

			return createServFailResponseDNSSEC(request, "DNSSEC validation failed: bogus signatures"), nil

		case dnssec.ValidationResultSecure:
			// Valid DNSSEC - set AD flag
			response.Res.AuthenticatedData = true
			logger.Debugf("DNSSEC validation succeeded for %s - AD flag set",
				request.Req.Question[0].Name)

		case dnssec.ValidationResultInsecure, dnssec.ValidationResultIndeterminate:
			// No DNSSEC or cannot validate - clear AD flag
			response.Res.AuthenticatedData = false
			logger.Debugf("DNSSEC validation result %s for %s - AD flag cleared",
				result.String(), request.Req.Question[0].Name)
		}
	}

	return response, nil
}

// createServFailResponseDNSSEC creates a SERVFAIL response for a DNSSEC validation failure
func createServFailResponseDNSSEC(request *model.Request, reason string) *model.Response {
	modelResp := model.NewResponseWithRcode(request, dns.RcodeServerFailure, model.ResponseTypeBLOCKED, reason)

	// Add EDE (Extended DNS Error) code for DNSSEC Bogus
	// RFC 8914: https://www.rfc-editor.org/rfc/rfc8914.html#section-5.2
	edeOption := &dns.EDNS0_EDE{
		InfoCode:  dns.ExtendedErrorCodeDNSBogus,
		ExtraText: reason,
	}

	// Add EDNS0 OPT record with EDE option
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(ednsUDPSize)
	opt.Option = append(opt.Option, edeOption)
	modelResp.Res.Extra = append(modelResp.Res.Extra, opt)

	return modelResp
}
