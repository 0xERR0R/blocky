package util

import "github.com/miekg/dns"

// RemoveEdns0Record removes the OPT record from the Extra section of the given message.
func RemoveEdns0Record(msg *dns.Msg) {
	if msg == nil {
		return
	}

	if msg.IsEdns0() == nil {
		return
	}

	if len(msg.Extra) > 0 {
		extra := make([]dns.RR, 0, len(msg.Extra))

		for _, rr := range msg.Extra {
			if rr.Header().Rrtype != dns.TypeOPT {
				extra = append(extra, rr)
			}
		}

		msg.Extra = extra
	}
}

// GetEdns0Record returns the OPT record from the Extra section of the given message.
func GetEdns0Record(msg *dns.Msg) *dns.OPT {
	if msg == nil {
		return nil
	}

	if res := msg.IsEdns0(); res != nil {
		return res
	}

	res := new(dns.OPT)
	res.Hdr.Name = "."
	res.Hdr.Rrtype = dns.TypeOPT
	msg.Extra = append(msg.Extra, res)

	return res
}

// HasEdns0Option checks if the given message contains an OPT record in the
// Extra section and if it contains the given option code.
func HasEdns0Option(msg *dns.Msg, code uint16) bool {
	if msg == nil {
		return false
	}

	if msg.IsEdns0() == nil {
		return false
	}

	opt := GetEdns0Record(msg)
	for _, o := range opt.Option {
		if o.Option() == code {
			return true
		}
	}

	return false
}

// GetEdns0Option returns the option with the given code from the OPT record in the
func GetEdns0Option(msg *dns.Msg, code uint16) dns.EDNS0 {
	if msg == nil {
		return nil
	}

	if msg.IsEdns0() == nil {
		return nil
	}

	opt := GetEdns0Record(msg)
	for _, o := range opt.Option {
		if o.Option() == code {
			return o
		}
	}

	return nil
}

// RemoveEdns0Option removes the option with the given code from the OPT record in the
func RemoveEdns0Option(msg *dns.Msg, code uint16) {
	if msg == nil {
		return
	}

	if msg.IsEdns0() == nil {
		return
	}

	opt := GetEdns0Record(msg)
	newOpts := make([]dns.EDNS0, 0, len(opt.Option))

	for _, o := range opt.Option {
		if o.Option() != code {
			newOpts = append(newOpts, o)
		}
	}

	opt.Option = newOpts

	if len(opt.Option) == 0 {
		RemoveEdns0Record(msg)
	}
}

// SetEdns0Option adds the given option to the OPT record in the Extra section of the
// given message. If the option already exists, it will be replaced.
func SetEdns0Option(msg *dns.Msg, opt dns.EDNS0) {
	if msg == nil {
		return
	}

	optRecord := GetEdns0Record(msg)
	newOpts := make([]dns.EDNS0, 0, len(optRecord.Option))

	for _, o := range optRecord.Option {
		if o.Option() != opt.Option() {
			newOpts = append(newOpts, o)
		}
	}

	newOpts = append(newOpts, opt)
	optRecord.Option = newOpts
}
