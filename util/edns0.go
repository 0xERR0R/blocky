package util

import (
	"fmt"
	"slices"

	"github.com/miekg/dns"
)

// EDNS0Option is an interface for all EDNS0 options as type constraint for generics.
type EDNS0Option interface {
	*dns.EDNS0_SUBNET | *dns.EDNS0_EDE | *dns.EDNS0_LOCAL | *dns.EDNS0_NSID | *dns.EDNS0_COOKIE | *dns.EDNS0_UL
	Option() uint16
}

// RemoveEdns0Record removes the OPT record from the Extra section of the given message.
// If the OPT record is removed, true will be returned.
func RemoveEdns0Record(msg *dns.Msg) bool {
	if msg == nil || msg.IsEdns0() == nil {
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

// GetEdns0Option returns the option with the given code from the OPT record in the
// Extra section of the given message.
// If the option is not found, nil will be returned.
func GetEdns0Option[T EDNS0Option](msg *dns.Msg) T {
	if msg == nil {
		return nil
	}

	opt := msg.IsEdns0()
	if opt == nil {
		return nil
	}

	var t T

	for _, o := range opt.Option {
		if o.Option() == t.Option() {
			t, ok := o.(T)
			if !ok {
				panic(fmt.Errorf("dns option with code %d is not of type %T", t.Option(), t))
			}

			return t
		}
	}

	return nil
}

// RemoveEdns0Option removes the option according to the given type from the OPT record
// in the Extra section of the given message.
// If there are no more options in the OPT record, the OPT record will be removed.
// If the option is successfully removed, true will be returned.
func RemoveEdns0Option[T EDNS0Option](msg *dns.Msg) bool {
	if msg == nil {
		return false
	}

	opt := msg.IsEdns0()
	if opt == nil {
		return false
	}

	res := false

	var t T

	for i, o := range opt.Option {
		if o.Option() == t.Option() {
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
// If the option is successfully set, true will be returned.
func SetEdns0Option(msg *dns.Msg, opt dns.EDNS0) bool {
	if msg == nil || opt == nil {
		return false
	}

	optRecord := msg.IsEdns0()

	if optRecord == nil {
		optRecord = new(dns.OPT)
		optRecord.Hdr.Name = "."
		optRecord.Hdr.Rrtype = dns.TypeOPT
		msg.Extra = append(msg.Extra, optRecord)
	}

	newOpts := make([]dns.EDNS0, 0, len(optRecord.Option)+1)

	for _, o := range optRecord.Option {
		if o.Option() != opt.Option() {
			newOpts = append(newOpts, o)
		}
	}

	newOpts = append(newOpts, opt)
	optRecord.Option = newOpts

	return true
}
