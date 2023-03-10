package config

import (
	"strconv"
	"time"

	"github.com/0xERR0R/blocky/log"
	"github.com/hako/durafmt"
	"golang.org/x/exp/constraints"
)

type Duration struct{ time.Duration }

func NewDuration[T constraints.Integer | time.Duration](value T) Duration {
	return Duration{Duration: time.Duration(value)}
}

func (c Duration) Cast() time.Duration {
	return c.Duration
}

func (c Duration) IsZero() bool {
	return c.Duration == 0
}

func (c Duration) SecondsU32() uint32 {
	return uint32(c.Seconds())
}

func (c Duration) String() string {
	return durafmt.Parse(c.Cast()).String()
}

func (c *Duration) UnmarshalText(data []byte) error {
	input := string(data)

	if minutes, err := strconv.Atoi(input); err == nil {
		// number without unit: use minutes to ensure back compatibility
		*c = NewDuration(time.Duration(minutes) * time.Minute)

		log.Log().Warnf("Setting a duration without a unit is deprecated. Please use '%s min' instead.", input)

		return nil
	}

	duration, err := time.ParseDuration(input)
	if err == nil {
		*c = NewDuration(duration)

		return nil
	}

	return err
}
