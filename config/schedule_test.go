package config

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Schedule", func() {
	var cfg Schedule

	BeforeEach(func() {
		hr, _ := parseHoursRange("09:00-17:00")

		cfg = Schedule{
			Days:        []day{day(time.Monday)},
			HoursRanges: []hoursRange{hr},
			Active:      false,
		}
	})

	Describe("day stringer", func() {
		When("valid day", func() {
			It("should return the correct day string", func() {
				day := cfg.Days[0].String()
				Expect(day).To(Equal(time.Monday.String()))
			})
		})
	})

	Describe("hoursRange stringer", func() {
		When("valid range", func() {
			It("should return the correct range string", func() {
				hr := cfg.HoursRanges[0].String()
				Expect(hr).To(Equal("09:00-17:00"))
			})
		})
	})

	Describe("parseDay", func() {
		When("valid day", func() {
			It("should return the correct weekday", func() {
				day, err := parseDay("Mon")
				Expect(err).Should(Succeed())
				Expect(day).To(Equal(time.Monday))

				day, err = parseDay("Fri")
				Expect(err).Should(Succeed())
				Expect(day).To(Equal(time.Friday))
			})
		})

		When("invalid day", func() {
			It("should return an error", func() {
				_, err := parseDay("invalid_day")
				Expect(err.Error()).To(Equal("invalid day: invalid_day"))
			})
		})
	})

	Describe("parseHoursRange", func() {
		When("valid hour range", func() {
			It("should return the correct hours range", func() {
				hr, err := parseHoursRange("09:00-17:00")
				Expect(err).Should(Succeed())
				Expect(hr.Start.Format("15:04")).To(Equal("09:00"))
				Expect(hr.End.Format("15:04")).To(Equal("17:00"))
			})
		})

		When("invalid hour range", func() {
			It("should return an error", func() {
				_, err := parseHoursRange("09-17:00")
				Expect(err.Error()).To(Equal("invalid start hour: 09-17:00"))
			})
		})

		When("invalid hours range format", func() {
			It("should return an error", func() {
				_, err := parseHoursRange("18:00")
				Expect(err.Error()).To(Equal("invalid hours range format: 18:00"))
			})
		})

		When("invalid start hour", func() {
			It("should return an error", func() {
				_, err := parseHoursRange("25:00-17:00")
				Expect(err.Error()).To(Equal("invalid start hour: 25:00-17:00"))
			})
		})

		When("with invalid end hour", func() {
			It("should return an error", func() {
				_, err := parseHoursRange("09:00-17:60")
				Expect(err.Error()).To(Equal("invalid end hour: 09:00-17:60"))
			})
		})

		When("with start hour after end hour", func() {
			It("should return an error", func() {
				_, err := parseHoursRange("20:00-08:00")
				Expect(err.Error()).To(Equal("start hour is after end hour: 20:00-08:00"))
			})
		})
	})

	Describe("isActive", func() {
		When("active schedule hour", func() {
			It("should return true", func() {
				fakeTime := getFakeTime(time.Monday, "10:00")
				active := cfg.isActive(fakeTime)
				Expect(active).To(BeTrue())
			})
		})

		When("active schedule start time hour ", func() {
			It("should return true", func() {
				fakeTime := getFakeTime(time.Monday, "09:00")
				active := cfg.isActive(fakeTime)
				Expect(active).To(BeTrue())
			})
		})

		When("inactive schedule hour", func() {
			It("should return true", func() {
				fakeTime := getFakeTime(time.Monday, "07:00")
				active := cfg.isActive(fakeTime)
				Expect(active).To(BeFalse())
			})
		})

		When("inactive schedule day", func() {
			It("should return false", func() {
				fakeTime := getFakeTime(time.Sunday, "09:00")
				active := cfg.isActive(fakeTime)
				Expect(active).To(BeFalse())
			})
		})
	})
})
