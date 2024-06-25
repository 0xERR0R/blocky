package config

import (
	"fmt"
	"strings"
	"time"
)

const (
	validHRParts = 2
)

// Schedule of active blocking
type Schedule struct {
	Days        []day        `yaml:"days"`
	HoursRanges []hoursRange `yaml:"hoursRanges"`
	Active      bool
}

type day time.Weekday

type hoursRange struct {
	Start time.Time
	End   time.Time
}

// String implements the fmt.Stringer interface
func (d day) String() string {
	return time.Weekday(d).String()
}

// String implements the fmt.Stringer interface
func (hr hoursRange) String() string {
	return hr.Start.Format("15:04") + "-" + hr.End.Format("15:04")
}

// UnmarshalText implements the encoding.TextUnmarshaler interface
func (d *day) UnmarshalText(text []byte) error {
	input := string(text)

	result, err := parseDay(input)
	if err != nil {
		return err
	}

	*d = day(result)

	return nil
}

// UnmarshalText implements the encoding.TextUnmarshaler interface
func (hr *hoursRange) UnmarshalText(text []byte) error {
	input := string(text)

	result, err := parseHoursRange(input)
	if err != nil {
		return err
	}

	*hr = result

	return nil
}

func (hr *hoursRange) setRefTime() {
	*hr = hoursRange{
		Start: getRefTime(hr.Start),
		End:   getRefTime(hr.End),
	}
}

func parseDay(day string) (time.Weekday, error) {
	daysMap := map[string]time.Weekday{
		"Mon": time.Monday, "Tue": time.Tuesday, "Wed": time.Wednesday,
		"Thu": time.Thursday, "Fri": time.Friday, "Sat": time.Saturday, "Sun": time.Sunday,
	}

	if day, exists := daysMap[day]; exists {
		return day, nil
	}

	return time.Sunday, fmt.Errorf("invalid day: %s", day)
}

func parseHoursRange(hours string) (hoursRange, error) {
	parts := strings.Split(hours, "-")

	if len(parts) != validHRParts {
		return hoursRange{}, fmt.Errorf("invalid hours range format: %s", hours)
	}

	start, err := time.Parse("15:04", parts[0])
	if err != nil {
		return hoursRange{}, fmt.Errorf("invalid start hour: %s", hours)
	}

	end, err := time.Parse("15:04", parts[1])
	if err != nil {
		return hoursRange{}, fmt.Errorf("invalid end hour: %s", hours)
	}

	if start.After(end) {
		return hoursRange{}, fmt.Errorf("start hour is after end hour: %s", hours)
	}

	return hoursRange{
		Start: start,
		End:   end,
	}, nil
}

func (s *Schedule) isActive(nowFunc func() time.Time) bool {
	now := nowFunc()

	dayActive := false
	curDay := now.Weekday()

	for _, d := range s.Days {
		if d == day(curDay) {
			dayActive = true

			break
		}
	}

	if !dayActive {
		return false
	}

	curTime := now

	for _, hrsRange := range s.HoursRanges {
		hrsRange.setRefTime()

		refTime := getRefTime(curTime)
		if refTime == hrsRange.Start {
			return true
		}

		if refTime.After(hrsRange.Start) && refTime.Before(hrsRange.End) {
			return true
		}
	}

	return false
}

func getRefTime(t time.Time) time.Time {
	return time.Date(0, 1, 1, t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
}
