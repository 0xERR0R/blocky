package util

import (
	"math"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// TTLInput is the input type for TTL values and consists of the following underlying types:
// int, uint, uint32, int64
type TTLInput interface {
	~int | ~uint | ~uint32 | ~int64
}

// ToTTL converts the input to a TTL of seconds as uint32.
//
// If the input is of underlying type time.Duration, the value is converted to seconds.
//
// If the input is negative, the TTL is set to 0.
//
// If the input is greater than the maximum value of uint32, the TTL is set to math.MaxUint32.
func ToTTL[T TTLInput](input T) uint32 {
	// use int64 as the intermediate type
	res := int64(input)

	// check if the input is of underlying type time.Duration
	if durType, ok := any(input).(interface{ Seconds() float64 }); ok {
		res = int64(durType.Seconds())
	}

	// check if the value is negative or greater than the maximum value of uint32
	if res < 0 {
		// there is no negative TTL
		return 0
	} else if res > math.MaxUint32 {
		// since TTL is a 32-bit unsigned integer, the maximum value is math.MaxUint32
		return math.MaxUint32
	}

	// return the value as uint32
	return uint32(res)
}

// ToTTLDuration converts the input to a time.Duration.
//
// If the input is of underlying type time.Duration, the value is returned as is.
//
// Otherwise the value is converted to seconds and returned as time.Duration.
func ToTTLDuration[T TTLInput](input T) time.Duration {
	return time.Duration(ToTTL(input)) * time.Second
}

// SetAnswerMinTTL sets the TTL of all answers in the message that are less than the specified minimum TTL to
// the minimum TTL.
func SetAnswerMinTTL[T TTLInput](msg *dns.Msg, min T) {
	minTTL := ToTTL(min)
	for _, answer := range msg.Answer {
		if atomic.LoadUint32(&answer.Header().Ttl) < minTTL {
			atomic.StoreUint32(&answer.Header().Ttl, minTTL)
		}
	}
}

// SetAnswerMaxTTL sets the TTL of all answers in the message that are greater than the specified maximum TTL
// to the maximum TTL.
func SetAnswerMaxTTL[T TTLInput](msg *dns.Msg, max T) {
	maxTTL := ToTTL(max)
	for _, answer := range msg.Answer {
		if atomic.LoadUint32(&answer.Header().Ttl) > maxTTL && maxTTL != 0 {
			atomic.StoreUint32(&answer.Header().Ttl, maxTTL)
		}
	}
}

// SetAnswerMinMaxTTL sets the TTL of all answers in the message that are less than the specified minimum TTL
// to the minimum TTL and the TTL of all answers that are greater than the specified maximum TTL to the maximum TTL.
func SetAnswerMinMaxTTL[T TTLInput, TT TTLInput](msg *dns.Msg, min T, max TT) {
	minTTL := ToTTL(min)
	maxTTL := ToTTL(max)

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
func AdjustAnswerTTL[T TTLInput](msg *dns.Msg, adjustment T) {
	minTTL := GetAnswerMinTTL(msg)
	adjustmentTTL := ToTTL(adjustment)

	for _, answer := range msg.Answer {
		headerTTL := atomic.LoadUint32(&answer.Header().Ttl)
		atomic.StoreUint32(&answer.Header().Ttl, headerTTL-minTTL+adjustmentTTL)
	}
}
