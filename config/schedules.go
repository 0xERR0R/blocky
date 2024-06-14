package config

import (
	"context"
	"time"

	"github.com/0xERR0R/blocky/evt"
	"github.com/0xERR0R/blocky/log"
	"github.com/sirupsen/logrus"
)

const (
	refreshInterval = time.Minute
)

// Schedules is the list of schedule for the defined blacklist
type Schedules map[string][]Schedule

// Refresh update Schedule to set the Active field boolean
func (s Schedules) Refresh(ctx context.Context, nowFn func() time.Time) {
	logger := log.PrefixedLog("refresh_schedules")

	s.setActive(nowFn, logger) // initial schedules refresh (after blocky start)
	if isNowFnSet(nowFn) {
		return
	}

	syncSchedulesWithSystemTime(s, nowFn, logger)
	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.setActive(nowFn, logger)

		case <-ctx.Done():
			return
		}
	}
}

func isNowFnSet(nowFn func() time.Time) bool {
	return nowFn != nil
}

func setNowFnWhenNil(nowFn func() time.Time) func() time.Time {
	if nowFn == nil {
		return time.Now
	}
	return nowFn
}

func syncSchedulesWithSystemTime(s Schedules, nowFn func() time.Time, logger *logrus.Entry) {
	waitTime := getWaitTimeBeforeNextMinute()
	time.Sleep(waitTime)

	s.setActive(nowFn, logger) // now in sync with system time
}

func getWaitTimeBeforeNextMinute() time.Duration {
	return time.Until(
		time.Date(
			time.Now().Year(),
			time.Now().Month(),
			time.Now().Day(),
			time.Now().Hour(),
			time.Now().Minute()+1, 0, 0, // next minute
			time.Now().Location(),
		),
	)
}

func (s Schedules) setActive(nowFn func() time.Time, logger *logrus.Entry) {
	nowFn = setNowFnWhenNil(nowFn)

	for group, schedList := range s {
		for i, schedule := range schedList {
			active := false
			activeStr := "inactive"

			if schedule.isActive(nowFn) {
				active = true
				activeStr = "active"
			}

			if schedule.Active != active {
				s[group][i] = Schedule{
					Days:        schedule.Days,
					HoursRanges: schedule.HoursRanges,
					Active:      active,
				}

				activeFlag := 0
				if active {
					activeFlag = 1
				}

				evt.Bus().Publish(evt.SchedulesActive, group, activeFlag)
				logger.Infof("group %s is now %s", group, activeStr)
			}
		}
	}
}

// IsActive checks if the schedules of the group is active at the current time
func (s Schedules) IsActive(group string, nowFn func() time.Time) bool {
	nowFn = setNowFnWhenNil(nowFn)

	for _, schedule := range s[group] {
		if schedule.isActive(nowFn) {
			return true
		}
	}

	return false
}
