package config

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Schedules", func() {
	const (
		group = "testGroup"
	)

	var (
		schedules Schedules
		ctx       context.Context
		cancelFn  context.CancelFunc
	)

	BeforeEach(func() {
		schedules = make(Schedules)
		ctx, cancelFn = context.WithCancel(context.Background())

		hr, _ := parseHoursRange("09:00-17:00")

		schedules[group] = []Schedule{
			{
				Days:        []day{day(time.Saturday)},
				HoursRanges: []hoursRange{hr},
			},
		}
	})

	AfterEach(func() {
		cancelFn()
	})

	Describe("refresh schedules loop", func() {
		It("should set the Active field", func() {
			go schedules.Refresh(ctx, nil)
			time.Sleep(time.Second)

			now := time.Now()
			weekDay := now.Weekday()
			hour := now.Hour()

			if weekDay == time.Saturday && hour >= 9 && hour < 17 {
				Expect(schedules[group][0].Active).To(BeTrue())
			} else {
				Expect(schedules[group][0].Active).To(BeFalse())
			}
		})

		It("should set the Active field to true when schedule is active", func() {
			fakeTime := getFakeTime(time.Saturday, "10:00")
			schedules.Refresh(ctx, fakeTime)
			Expect(schedules[group][0].Active).To(BeTrue())
		})

		It("should set the Active field to false when schedule is inactive", func() {
			fakeTime := getFakeTime(time.Saturday, "19:00")
			schedules[group][0].Active = true
			schedules.Refresh(ctx, fakeTime)
			Expect(schedules[group][0].Active).To(BeFalse())
		})
	})

	Describe("IsActive", func() {
		When("schedule is active", func() {
			It("should return true", func() {
				fakeTime := getFakeTime(time.Saturday, "10:00")
				isActive := schedules.IsActive(group, fakeTime)
				Expect(isActive).To(BeTrue())
			})
		})

		When("schedule is inactive", func() {
			It("should return false", func() {
				fakeTime := getFakeTime(time.Sunday, "10:00")
				isActive := schedules.IsActive(group, fakeTime)
				Expect(isActive).To(BeFalse())
			})
		})
	})
})

func getFakeTime(wk time.Weekday, hr string) func() time.Time {
	return func() time.Time {
		t, err := time.Parse("15:04", hr)
		if err != nil {
			panic(err)
		}

		return getRefTime(t).AddDate(0, 0, int(wk)+1)
	}
}
