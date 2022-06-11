package resolver

import (
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/miekg/dns"
)

type EdeResolver struct {
	Resolver
	enabled      bool
	mainResolver Resolver
}

func NewEdeResolver(cfg config.Config, r Resolver) Resolver {
	return &EdeResolver{
		enabled:      cfg.EdeEnabled,
		mainResolver: r,
	}
}

func (r *EdeResolver) Resolve(request *model.Request) (*model.Response, error) {
	res, err := r.mainResolver.Resolve(request)

	if r.enabled {
		addExtraReasoning(res)
	}

	return res, err
}

func (r *EdeResolver) Configuration() (result []string) {
	if r.enabled {
		result = []string{"activated"}
	} else {
		result = []string{"deactivated"}
	}

	return result
}

func addExtraReasoning(res *model.Response) {
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.Option = append(opt.Option, convertExtendedError(res))
	res.Res.Extra = append(res.Res.Extra, opt)
}

func convertExtendedError(input *model.Response) *dns.EDNS0_EDE {
	return &dns.EDNS0_EDE{
		InfoCode:  convertToExtendedErrorCode(input.RType),
		ExtraText: input.Reason,
	}
}

func convertToExtendedErrorCode(input model.ResponseType) uint16 {
	switch input {
	case model.ResponseTypeRESOLVED:
		return dns.ExtendedErrorCodeOther
	case model.ResponseTypeCACHED:
		return dns.ExtendedErrorCodeCachedError
	case model.ResponseTypeCONDITIONAL:
		return dns.ExtendedErrorCodeOther
	case model.ResponseTypeCUSTOMDNS:
		return dns.ExtendedErrorCodeForgedAnswer
	case model.ResponseTypeHOSTSFILE:
		return dns.ExtendedErrorCodeForgedAnswer
	case model.ResponseTypeBLOCKED:
		return dns.ExtendedErrorCodeBlocked
	case model.ResponseTypeFILTERED:
		return dns.ExtendedErrorCodeFiltered
	default:
		return dns.ExtendedErrorCodeOther
	}
}
