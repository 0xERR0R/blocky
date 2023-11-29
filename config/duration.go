package config

import (
	"strconv"
	"time"

	"github.com/0xERR0R/blocky/log"
	"github.com/hako/durafmt"
)

// Duration is a wrapper for time.Duration to support yaml unmarshalling
type Duration time.Duration

// ToDuration converts Duration to time.Duration
func (c Duration) ToDuration() time.Duration {
	return time.Duration(c)
}

// IsAboveZero returns true if duration is strictly greater than zero.
func (c Duration) IsAboveZero() bool {
	return c.ToDuration() > 0
}

// IsAtLeastZero returns true if duration is greater or equal to zero.
func (c Duration) IsAtLeastZero() bool {
	return c.ToDuration() >= 0
}

// Seconds returns duration in seconds
func (c Duration) Seconds() float64 {
	return c.ToDuration().Seconds()
}

// SecondsU32 returns duration in seconds as uint32
func (c Duration) SecondsU32() uint32 {
	return uint32(c.Seconds())
}

// String implements `fmt.Stringer`
func (c Duration) String() string {
	return durafmt.Parse(c.ToDuration()).String()
}

// UnmarshalText implements `encoding.TextUnmarshaler`.
func (c *Duration) UnmarshalText(data []byte) error {
	input := string(data)

	if minutes, err := strconv.Atoi(input); err == nil {
		// number without unit: use minutes to ensure back compatibility
		*c = Duration(time.Duration(minutes) * time.Minute)

		log.Log().Warnf("Setting a duration without a unit is deprecated. Please use '%s min' instead.", input)

		return nil
	}

	duration, err := time.ParseDuration(input)
	if err == nil {
		*c = Duration(duration)

		return nil
	}

	return err
}
