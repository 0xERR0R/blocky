package util

import (
	"slices"

	"github.com/miekg/dns"
)

// EDNS0Option is an interface for all EDNS0 options as type constraint for generics.
type EDNS0Option interface {
	*dns.EDNS0_SUBNET | *dns.EDNS0_EDE | *dns.EDNS0_LOCAL | *dns.EDNS0_NSID | *dns.EDNS0_COOKIE | *dns.EDNS0_UL
	Option() uint16
}

// RemoveEdns0Record removes the OPT record from the Extra section of the given message.
func RemoveEdns0Record(msg *dns.Msg) bool {
	if msg == nil || msg.IsEdns0() == nil || len(msg.Extra) == 0 {
		return false
	}

	for i, rr := range msg.Extra {
		if rr.Header().Rrtype == dns.TypeOPT {
			msg.Extra = slices.Delete(msg.Extra, i, i+1)

			return true
		}
	}

	return false
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

// GetEdns0Option returns the option with the given code from the OPT record in the
// Extra section of the given message.
func GetEdns0Option[T EDNS0Option](msg *dns.Msg) T {
	code := getCode[T](msg)
	if code == 0 {
		return nil
	}

	opt := GetEdns0Record(msg)
	for _, o := range opt.Option {
		if o.Option() == code {
			t, ok := o.(T)
			if !ok {
				panic(fmt.Errorf("dns option with code %d is not of type %T", code, t))
			}
		}
	}

	return nil
}

// RemoveEdns0Option removes the option according to the given type from the OPT record
// in the Extra section of the given message.
// If the option doesn't exist, false will be returned.
func RemoveEdns0Option[T EDNS0Option](msg *dns.Msg) bool {
	code := getCode[T](msg)
	if code == 0 {
		return false
	}

	res := false

	opt := GetEdns0Record(msg)
	for i, o := range opt.Option {
		if o.Option() == code {
			opt.Option = slices.Delete(opt.Option, i, i+1)

			res = true

			break
		}
	}

	if len(opt.Option) == 0 {
		RemoveEdns0Record(msg)
	}

	return res
}

// SetEdns0Option adds the given option to the OPT record in the Extra section of the
// given message.
// If the option already exists, it will be replaced.
func SetEdns0Option(msg *dns.Msg, opt dns.EDNS0) {
	if msg == nil {
		return
	}

	optRecord := GetEdns0Record(msg)

	newOpts := make([]dns.EDNS0, 0, len(optRecord.Option)+1)

	for _, o := range optRecord.Option {
		if o.Option() != opt.Option() {
			newOpts = append(newOpts, o)
		}
	}

	newOpts = append(newOpts, opt)
	optRecord.Option = newOpts
}

// getCode returns the option code for the given option type.
// It is used to get the option code as uint16 for generics.
// If the given message is nil or doesn't contain an OPT record, 0 will be returned.
func getCode[T EDNS0Option](msg *dns.Msg) uint16 {
	if msg == nil || msg.IsEdns0() == nil {
		return 0
	}

	var t T

	return t.Option()
}
