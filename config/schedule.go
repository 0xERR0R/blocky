package config

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/log"
)

const (
	daysPerWeek    = 7
	minutesPerHour = 60
)

// Weekday represents a day of the week for schedule configuration.
type Weekday time.Weekday

func lookupWeekday(name string) (time.Weekday, bool) {
	days := map[string]time.Weekday{
		"sun": time.Sunday,
		"mon": time.Monday,
		"tue": time.Tuesday,
		"wed": time.Wednesday,
		"thu": time.Thursday,
		"fri": time.Friday,
		"sat": time.Saturday,
	}

	d, ok := days[name]

	return d, ok
}

// UnmarshalText implements `encoding.TextUnmarshaler`.
func (w *Weekday) UnmarshalText(data []byte) error {
	day, ok := lookupWeekday(strings.ToLower(strings.TrimSpace(string(data))))
	if !ok {
		return fmt.Errorf("invalid weekday '%s', use: mon, tue, wed, thu, fri, sat, sun", string(data))
	}

	*w = Weekday(day)

	return nil
}

func (w Weekday) String() string {
	return time.Weekday(w).String()
}

// Schedule defines a time-based schedule for blocking rules.
type Schedule struct {
	Start    string    `yaml:"start"`
	End      string    `yaml:"end"`
	Weekdays []Weekday `yaml:"weekdays"`

	// Precomputed by validate() for allocation-free hot-path evaluation.
	startMin    int
	endMin      int
	weekdayMask uint8
}

// parseTimeOfDay parses an "HH:MM" string into hours and minutes.
func parseTimeOfDay(s string) (hour, minute int, err error) {
	t, err := time.Parse("15:04", s)
	if err != nil || t.Format("15:04") != s {
		return 0, 0, fmt.Errorf("invalid time format '%s', expected HH:MM", s)
	}

	return t.Hour(), t.Minute(), nil
}

func (s *Schedule) validate() error {
	// Both omitted = full day, both set = time range; partial = error
	if (s.Start == "") != (s.End == "") {
		return errors.New("both start and end must be set, or both omitted for full-day schedule")
	}

	if s.Start != "" {
		if _, _, err := parseTimeOfDay(s.Start); err != nil {
			return err
		}
	}

	if s.End != "" {
		if _, _, err := parseTimeOfDay(s.End); err != nil {
			return err
		}
	}

	if len(s.Weekdays) == 0 {
		return errors.New("schedule weekdays are required (use: mon, tue, wed, thu, fri, sat, sun)")
	}

	seen := make(map[Weekday]bool, len(s.Weekdays))

	for _, wd := range s.Weekdays {
		if seen[wd] {
			log.Log().Warnf("schedule contains duplicate weekday '%s', possible typo?", wd)
		}

		seen[wd] = true
	}

	s.compile()

	return nil
}

// compile pre-parses Start/End and builds weekdayMask. Called by validate().
func (s *Schedule) compile() {
	if s.Start != "" {
		if sh, sm, err := parseTimeOfDay(s.Start); err == nil {
			s.startMin = sh*minutesPerHour + sm
		}

		if eh, em, err := parseTimeOfDay(s.End); err == nil {
			s.endMin = eh*minutesPerHour + em
		}
	}

	for _, wd := range s.Weekdays {
		s.weekdayMask |= 1 << uint(time.Weekday(wd))
	}
}

// IsActive returns true if the schedule is active at the given time.
func (s *Schedule) IsActive(now time.Time) bool {
	todayBit := uint8(1) << uint(now.Weekday())

	if s.Start == "" {
		return s.weekdayMask&todayBit != 0
	}

	nowMin := now.Hour()*minutesPerHour + now.Minute()

	if s.startMin <= s.endMin {
		// Same-day range (e.g. 09:00 - 17:00), or zero-length window
		// (start == end), which is correctly never active.
		return s.weekdayMask&todayBit != 0 && nowMin >= s.startMin && nowMin < s.endMin
	}

	// Overnight range (e.g. 22:00 - 07:00): active if today is scheduled
	// and we're past the start time, OR yesterday was scheduled and we're
	// before the end time.
	yesterdayBit := uint8(1) << uint((now.Weekday()+daysPerWeek-1)%daysPerWeek)
	todayActive := s.weekdayMask&todayBit != 0 && nowMin >= s.startMin
	yesterdayActive := s.weekdayMask&yesterdayBit != 0 && nowMin < s.endMin

	return todayActive || yesterdayActive
}
