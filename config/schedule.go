package config

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/log"
)

const daysPerWeek = 7

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

// isFullDay returns true if the schedule covers the entire day
// (both start and end omitted, or both set to "00:00").
func (s *Schedule) isFullDay() bool {
	if s.Start == "" && s.End == "" {
		return true
	}

	if s.Start != "" && s.End != "" {
		startH, startM, err1 := parseTimeOfDay(s.Start)
		endH, endM, err2 := parseTimeOfDay(s.End)

		if err1 == nil && err2 == nil && startH == 0 && startM == 0 && endH == 0 && endM == 0 {
			return true
		}
	}

	return false
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

	return nil
}

// IsActive returns true if the schedule is active at the given time.
func (s *Schedule) IsActive(now time.Time) bool {
	if s.isFullDay() {
		// Full-day schedule: just check weekday
		today := now.Weekday()

		for _, wd := range s.Weekdays {
			if time.Weekday(wd) == today {
				return true
			}
		}

		return false
	}

	startH, startM, _ := parseTimeOfDay(s.Start)
	endH, endM, _ := parseTimeOfDay(s.End)

	nowMinutes := toMinutes(now.Hour(), now.Minute())
	startMinutes := toMinutes(startH, startM)
	endMinutes := toMinutes(endH, endM)

	if !s.weekdayMatch(now, nowMinutes, startMinutes, endMinutes) {
		return false
	}

	if startMinutes <= endMinutes {
		// Same-day range (e.g. 09:00 - 17:00)
		return nowMinutes >= startMinutes && nowMinutes < endMinutes
	}

	// Overnight range (e.g. 22:00 - 07:00)
	return nowMinutes >= startMinutes || nowMinutes < endMinutes
}

func toMinutes(hours, mins int) int {
	return hours*60 + mins
}

func (s *Schedule) weekdayMatch(now time.Time, nowMinutes, startMinutes, endMinutes int) bool {
	today := now.Weekday()

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
