package util

import (
	"math"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// ttlInput is the input type for TTL values and consists of the following types:
// int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, string, time.Duration
type ttlInput interface {
	int | int8 | int16 | int32 | int64 | uint | uint8 | uint32 | uint64 | string | time.Duration
}

// ToTTL converts the input to a TTL of seconds as uint32.
func ToTTL[T ttlInput](input T) uint32 {
	// use int64 as the intermediate type
	res := int64(0)

	switch typedInput := any(input).(type) {
	case string:
		if seconds, err := strconv.Atoi(typedInput); err == nil {
			res = int64(seconds)
		} else {
			if duration, err := time.ParseDuration(typedInput); err == nil {
				res = int64(duration.Seconds())
			}
		}
	case time.Duration:
		res = int64(typedInput.Seconds())
	case int:
		res = int64(typedInput)
	case int8:
		res = int64(typedInput)
	case int16:
		res = int64(typedInput)
	case int32:
		res = int64(typedInput)
	case int64:
		res = typedInput
	case uint:
		res = int64(typedInput)
	case uint8:
		res = int64(typedInput)
	case uint16:
		res = int64(typedInput)
	case uint32:
		res = int64(typedInput)
	case uint64:
		res = int64(typedInput)
	default:
		panic("invalid TTL value input type")
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

// SetAnswerMinTTL sets the TTL of all answers in the message that are less than the specified minimum TTL to
// the minimum TTL.
func SetAnswerMinTTL[T ttlInput](msg *dns.Msg, min T) {
	minTTL := ToTTL(min)
	for _, answer := range msg.Answer {
		if atomic.LoadUint32(&answer.Header().Ttl) < minTTL {
			atomic.StoreUint32(&answer.Header().Ttl, minTTL)
		}
	}
}

// SetAnswerMaxTTL sets the TTL of all answers in the message that are greater than the specified maximum TTL
// to the maximum TTL.
func SetAnswerMaxTTL[T ttlInput](msg *dns.Msg, max T) {
	maxTTL := ToTTL(max)
	for _, answer := range msg.Answer {
		if atomic.LoadUint32(&answer.Header().Ttl) > maxTTL && maxTTL != 0 {
			atomic.StoreUint32(&answer.Header().Ttl, maxTTL)
		}
	}
}

// SetAnswerMinMaxTTL sets the TTL of all answers in the message that are less than the specified minimum TTL
// to the minimum TTL and the TTL of all answers that are greater than the specified maximum TTL to the maximum TTL.
func SetAnswerMinMaxTTL[T ttlInput](msg *dns.Msg, min, max T) {
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
func AdjustAnswerTTL[T ttlInput](msg *dns.Msg, adjustment T) {
	minTTL := GetAnswerMinTTL(msg)
	adjustmentTTL := ToTTL(adjustment)

	for _, answer := range msg.Answer {
		headerTTL := atomic.LoadUint32(&answer.Header().Ttl)
		atomic.StoreUint32(&answer.Header().Ttl, headerTTL-minTTL+adjustmentTTL)
	}
}
