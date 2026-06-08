package resolver

import (
	"context"
	"unicode/utf8"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"
)

// maxEDETextLength bounds the EDE extra text. The reason now embeds the matched
// denylist rule, which is unbounded for regex entries. dns.Msg.Truncate keeps
// the OPT record and subtracts its full length from the size budget, so an
// oversized extra text would shrink (or eliminate) the room left for the actual
// answer on a size-limited (typically UDP) response. Bounding it here keeps the
// OPT small; the full reason is still recorded in the query log.
const maxEDETextLength = 200

// A EDEResolver is responsible for adding the reason for the response as EDNS0 option
type EDEResolver struct {
	configurable[*config.EDE]
	NextResolver
	typed
}

// NewEDEResolver creates new resolver instance which adds the reason for
// the response as EDNS0 option to the response if it is enabled in the configuration
func NewEDEResolver(cfg config.EDE) *EDEResolver {
	return &EDEResolver{
		configurable: withConfig(&cfg),
		typed:        withType("extended_error_code"),
	}
}

// Resolve adds the reason as EDNS0 option to the response of the next resolver
// if it is enabled in the configuration
func (r *EDEResolver) Resolve(ctx context.Context, request *model.Request) (*model.Response, error) {
	if !r.cfg.Enable {
		return r.next.Resolve(ctx, request)
	}

	resp, err := r.next.Resolve(ctx, request)
	if err != nil {
		return nil, err
	}

	r.addExtraReasoning(resp)

	return resp, nil
}

// addExtraReasoning adds the reason for the response as EDNS0 option
func (r *EDEResolver) addExtraReasoning(res *model.Response) {
	infocode := res.RType.ToExtendedErrorCode()

	if infocode == dns.ExtendedErrorCodeOther {
		// dns.ExtendedErrorCodeOther seams broken in some clients
		return
	}

	edeOption := new(dns.EDNS0_EDE)
	edeOption.InfoCode = infocode
	edeOption.ExtraText = truncateText(res.Reason, maxEDETextLength)

	util.SetEdns0Option(res.Res, edeOption)
}

// truncateText limits s to at most maxLen bytes, cutting on a UTF-8 rune
// boundary so it never emits an invalid (partial) rune.
func truncateText(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}

	cut := maxLen
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}

	return s[:cut]
}
