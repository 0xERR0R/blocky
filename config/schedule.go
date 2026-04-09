package config

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	minutesPerHour = 60
	daysPerWeek    = 7
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
}

// parseTimeOfDay parses an "HH:MM" string into hours and minutes.
func parseTimeOfDay(s string) (hour, minute int, err error) {
	var h, m int

	n, err := fmt.Sscanf(s, "%d:%d", &h, &m)
	if err != nil || n != 2 {
		return 0, 0, fmt.Errorf("invalid time format '%s', expected HH:MM", s)
	}

	if h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, fmt.Errorf("invalid time '%s': hours must be 0-23, minutes 0-59", s)
	}

	return h, m, nil
}

func (s *Schedule) validate() error {
	if s.Start == "" {
		return errors.New("schedule start time is required")
	}

	if s.End == "" {
		return errors.New("schedule end time is required")
	}

	if _, _, err := parseTimeOfDay(s.Start); err != nil {
		return err
	}

	if _, _, err := parseTimeOfDay(s.End); err != nil {
		return err
	}

	if len(s.Weekdays) == 0 {
		return errors.New("schedule weekdays are required (use: mon, tue, wed, thu, fri, sat, sun)")
	}

	return nil
}

// IsActive returns true if the schedule is active at the given time.
func (s *Schedule) IsActive(now time.Time) bool {
	if !s.weekdayMatch(now) {
		return false
	}

	startH, startM, _ := parseTimeOfDay(s.Start)
	endH, endM, _ := parseTimeOfDay(s.End)

	nowMinutes := toMinutes(now.Hour(), now.Minute())
	startMinutes := toMinutes(startH, startM)
	endMinutes := toMinutes(endH, endM)

	if startMinutes <= endMinutes {
		// Same-day range (e.g. 09:00 - 17:00)
		return nowMinutes >= startMinutes && nowMinutes < endMinutes
	}

	// Overnight range (e.g. 22:00 - 07:00)
	return nowMinutes >= startMinutes || nowMinutes < endMinutes
}

func toMinutes(hours, mins int) int {
	return hours*minutesPerHour + mins
}

func (s *Schedule) weekdayMatch(now time.Time) bool {
	today := now.Weekday()

	startH, startM, _ := parseTimeOfDay(s.Start)
	endH, endM, _ := parseTimeOfDay(s.End)
	startMinutes := toMinutes(startH, startM)
	endMinutes := toMinutes(endH, endM)
	nowMinutes := toMinutes(now.Hour(), now.Minute())

	for _, wd := range s.Weekdays {
		if time.Weekday(wd) == today {
			if startMinutes <= endMinutes {
				// Same-day range: simple match
				return true
			}

			// Overnight range: today matches for the "start" portion (after startMinutes)
			if nowMinutes >= startMinutes {
				return true
			}
		}

		// For overnight schedules, check if yesterday was a scheduled day
		// and we're in the "morning" portion (before endMinutes)
		if startMinutes > endMinutes {
			yesterday := (today + daysPerWeek - 1) % daysPerWeek
			if time.Weekday(wd) == yesterday && nowMinutes < endMinutes {
				return true
			}
		}
	}

	return false
}


