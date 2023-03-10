package config

import (
	"strconv"
	"time"

	"github.com/0xERR0R/blocky/log"
	"github.com/hako/durafmt"
)

type Duration time.Duration

func (c Duration) ToDuration() time.Duration {
	return time.Duration(c)
}

func (c Duration) IsZero() bool {
	return c.ToDuration() == 0
}

func (c Duration) Seconds() float64 {
	return c.ToDuration().Seconds()
}

func (c Duration) SecondsU32() uint32 {
	return uint32(c.Seconds())
}

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
