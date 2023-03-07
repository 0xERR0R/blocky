package resolver

import (
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/miekg/dns"
)

type EdeResolver struct {
	NextResolver
	config config.EdeConfig
}

func NewEdeResolver(cfg config.EdeConfig) ChainedResolver {
	return &EdeResolver{
		config: cfg,
	}
}

func (r *EdeResolver) Resolve(request *model.Request) (*model.Response, error) {
	resp, err := r.next.Resolve(request)
	if err != nil {
		return nil, err
	}

	if r.config.Enable {
		addExtraReasoning(resp)
	}

	return resp, nil
}

func (r *EdeResolver) Configuration() (result []string) {
	if !r.config.Enable {
		return configDisabled
	}

	return configEnabled
}

func addExtraReasoning(res *model.Response) {
	// dns.ExtendedErrorCodeOther seams broken in some clients
	infocode := convertToExtendedErrorCode(res.RType)
	if infocode > 0 {
		opt := new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		opt.Option = append(opt.Option, convertExtendedError(res, infocode))
		res.Res.Extra = append(res.Res.Extra, opt)
	}
}

func convertExtendedError(input *model.Response, infocode uint16) *dns.EDNS0_EDE {
	return &dns.EDNS0_EDE{
		InfoCode:  infocode,
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
		return dns.ExtendedErrorCodeForgedAnswer
	case model.ResponseTypeCUSTOMDNS:
		return dns.ExtendedErrorCodeForgedAnswer
	case model.ResponseTypeHOSTSFILE:
		return dns.ExtendedErrorCodeForgedAnswer
	case model.ResponseTypeNOTFQDN:
		return dns.ExtendedErrorCodeBlocked
	case model.ResponseTypeBLOCKED:
		return dns.ExtendedErrorCodeBlocked
	case model.ResponseTypeFILTERED:
		return dns.ExtendedErrorCodeFiltered
	case model.ResponseTypeSPECIAL:
		return dns.ExtendedErrorCodeFiltered
	default:
		return dns.ExtendedErrorCodeOther
	}
}
