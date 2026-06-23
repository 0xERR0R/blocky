package resolver

import (
	"context"
	"fmt"
	"log/slog"

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

		logger.InfoContext(ctx, fmt.Sprintf("DNSSEC resolver initialized with %d root trust anchor(s)",
			len(trustAnchors.GetRootTrustAnchors())))
	}

	return r, nil
}

// Resolve validates DNSSEC signatures if validation is enabled
//
//nolint:funlen // length is dominated by the GHSA-x845 validation-scope comment, not logic
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
			logger.DebugContext(ctx, "DNSSEC DO bit set for query (existing EDNS0)",
				slog.String("qname", request.Req.Question[0].Name))
		} else {
			// No EDNS0 present - add it with DO bit
			request.Req.SetEdns0(ednsUDPSize, true)
			logger.DebugContext(ctx, "DNSSEC DO bit set for query (new EDNS0)",
				slog.String("qname", request.Req.Question[0].Name))
		}
	}

	// Get response from next resolver (upstream)
	response, err := r.next.Resolve(ctx, request)
	if err != nil {
		return nil, err
	}

	// Validate DNSSEC if enabled and validator is available
	if r.cfg.Validate && r.validator != nil && len(request.Req.Question) > 0 {
		// Only public-upstream answers carry a chain of trust in the public DNS hierarchy and
		// form the GHSA-x845 attack surface, so validate exactly those: RESOLVED, plus cached
		// upstream answers re-served as CACHED (re-validated on every hit). Every other response
		// type that can reach this resolver from below is trusted-local or synthesized -
		// conditional-upstream private/split-horizon zones (CONDITIONAL), special-use names like
		// localhost (SPECIAL), DNS64-synthesized AAAA (SYNTHESIZED). Those are inherently unsigned
		// with no public chain of trust, so the post-GHSA-x845 handling would classify them bogus
		// - the whole namespace sits under the default root trust anchor - and turn every such
		// lookup into SERVFAIL (#2126). Mirror the rebinding resolver's response-type whitelist
		// and skip validation for them, clearing AD since we have not authenticated them. The
		// RType is assigned by blocky's own resolvers, never by the (attacker-controlled) upstream
		// answer, so a poisoned public answer cannot mislabel itself out of validation.
		if response != nil && response.Res != nil &&
			response.RType != model.ResponseTypeRESOLVED && response.RType != model.ResponseTypeCACHED {
			response.Res.AuthenticatedData = false
			logger.DebugContext(ctx, "skipping DNSSEC validation for trusted-local/synthesized response",
				slog.String("response_type", response.RType.String()),
				slog.String("qname", request.Req.Question[0].Name))

			return response, nil
		}

		// Preserve the originating client's identity so DS/DNSKEY sub-queries issued
		// during validation resolve from the same upstream view as the answer.
		validationCtx := dnssec.WithClientContext(ctx, request.ClientIP, request.ClientNames, request.RequestClientID)
		result := r.validator.ValidateResponse(validationCtx, response.Res, request.Req.Question[0])

		logger.DebugContext(ctx, "DNSSEC validation result",
			slog.String("qname", request.Req.Question[0].Name),
			slog.String("result", result.String()))

		switch result {
		case dnssec.ValidationResultBogus:
			// Invalid DNSSEC - return SERVFAIL
			logger.WarnContext(ctx, fmt.Sprintf("DNSSEC validation failed for %s - returning SERVFAIL",
				request.Req.Question[0].Name))

			return createServFailResponseDNSSEC(request, "DNSSEC validation failed: bogus signatures"), nil

		case dnssec.ValidationResultSecure:
			// Valid DNSSEC - set AD flag
			response.Res.AuthenticatedData = true
			logger.DebugContext(ctx, "DNSSEC validation succeeded - AD flag set",
				slog.String("qname", request.Req.Question[0].Name))

		case dnssec.ValidationResultInsecure, dnssec.ValidationResultIndeterminate:
			// No DNSSEC or cannot validate - clear AD flag
			response.Res.AuthenticatedData = false
			logger.DebugContext(ctx, "DNSSEC validation result - AD flag cleared",
				slog.String("result", result.String()),
				slog.String("qname", request.Req.Question[0].Name))
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
