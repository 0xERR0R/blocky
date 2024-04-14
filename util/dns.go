package util

import (
	"math"
	"sync/atomic"

	"github.com/miekg/dns"
)

// SetAnswerMinTTL sets the TTL of all answers in the message that are less than the specified minimum TTL to
// the minimum TTL.
func SetAnswerMinTTL(msg *dns.Msg, minTTL uint32) {
	for _, answer := range msg.Answer {
		if atomic.LoadUint32(&answer.Header().Ttl) < minTTL {
			atomic.StoreUint32(&answer.Header().Ttl, minTTL)
		}
	}
}

// SetAnswerMaxTTL sets the TTL of all answers in the message that are greater than the specified maximum TTL
// to the maximum TTL.
func SetAnswerMaxTTL(msg *dns.Msg, maxTTL uint32) {
	for _, answer := range msg.Answer {
		if atomic.LoadUint32(&answer.Header().Ttl) > maxTTL && maxTTL != 0 {
			atomic.StoreUint32(&answer.Header().Ttl, maxTTL)
		}
	}
}

// SetAnswerMinMaxTTL sets the TTL of all answers in the message that are less than the specified minimum TTL
// to the minimum TTL and the TTL of all answers that are greater than the specified maximum TTL to the maximum TTL.
func SetAnswerMinMaxTTL(msg *dns.Msg, minTTL uint32, maxTTL uint32) {
	for _, answer := range msg.Answer {
		headerTTL := atomic.LoadUint32(&answer.Header().Ttl)
		if headerTTL < minTTL {
			atomic.StoreUint32(&answer.Header().Ttl, minTTL)
		} else if headerTTL > maxTTL && maxTTL != 0 {
			atomic.StoreUint32(&answer.Header().Ttl, maxTTL)
		}
	}
}

// GetMinAnswerTTL returns the lowest TTL of all answers in the message.
func GetAnswerMinTTL(msg *dns.Msg) uint32 {
	var minTTL atomic.Uint32
	// initialize minTTL with the maximum value of uint32
	minTTL.Store(math.MaxUint32)

	for _, answer := range msg.Answer {
		headerTTL := atomic.LoadUint32(&answer.Header().Ttl)
		if headerTTL < minTTL.Load() {
			minTTL.Store(headerTTL)
		}
	}

	return minTTL.Load()
}

// AdjustAnswerTTL adjusts the TTL of all answers in the message by the difference between the lowest TTL
// and the answer's TTL plus the specified adjustment.
func AdjustAnswerTTL(msg *dns.Msg, adjustment uint32) {
	minTTL := GetAnswerMinTTL(msg)

	for _, answer := range msg.Answer {
		headerTTL := atomic.LoadUint32(&answer.Header().Ttl)
		atomic.StoreUint32(&answer.Header().Ttl, headerTTL-minTTL+adjustment)
	}
}
