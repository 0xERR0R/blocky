package config

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Schedule", func() {
	suiteBeforeEach()

	Describe("Weekday UnmarshalText", func() {
		It("should parse valid weekdays", func() {
			var w Weekday
			Expect(w.UnmarshalText([]byte("mon"))).Should(Succeed())
			Expect(time.Weekday(w)).Should(Equal(time.Monday))
		})

		It("should be case insensitive", func() {
			var w Weekday
			Expect(w.UnmarshalText([]byte("FRI"))).Should(Succeed())
			Expect(time.Weekday(w)).Should(Equal(time.Friday))
		})

		It("should reject invalid weekdays", func() {
			var w Weekday
			err := w.UnmarshalText([]byte("invalid"))
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("invalid weekday"))
		})
	})

	Describe("Schedule validate", func() {
		It("should accept valid schedule", func() {
			s := Schedule{
				Start:    "22:00",
				End:      "07:00",
				Weekdays: []Weekday{Weekday(time.Monday), Weekday(time.Friday)},
			}
			Expect(s.validate()).Should(Succeed())
		})

		It("should reject missing start", func() {
			s := Schedule{
				End:      "07:00",
				Weekdays: []Weekday{Weekday(time.Monday)},
			}
			Expect(s.validate()).Should(MatchError(ContainSubstring("start time is required")))
		})

		It("should reject missing end", func() {
			s := Schedule{
				Start:    "22:00",
				Weekdays: []Weekday{Weekday(time.Monday)},
			}
			Expect(s.validate()).Should(MatchError(ContainSubstring("end time is required")))
		})

		It("should reject missing weekdays", func() {
			s := Schedule{
				Start: "22:00",
				End:   "07:00",
			}
			Expect(s.validate()).Should(MatchError(ContainSubstring("weekdays are required")))
		})

		It("should reject invalid time format", func() {
			s := Schedule{
				Start:    "25:00",
				End:      "07:00",
				Weekdays: []Weekday{Weekday(time.Monday)},
			}
			Expect(s.validate()).Should(HaveOccurred())
		})
	})

	Describe("Schedule IsActive", func() {
		When("same-day range (09:00 - 17:00)", func() {
			var s Schedule
			BeforeEach(func() {
				s = Schedule{
					Start:    "09:00",
					End:      "17:00",
					Weekdays: []Weekday{Weekday(time.Monday), Weekday(time.Tuesday), Weekday(time.Wednesday)},
				}
			})

			It("should be active during the range on a matching day", func() {
				// Monday at 12:00
				now := time.Date(2026, 4, 6, 12, 0, 0, 0, time.Local)
				Expect(now.Weekday()).Should(Equal(time.Monday))
				Expect(s.IsActive(now)).Should(BeTrue())
			})

			It("should not be active before the range", func() {
				// Monday at 08:00
				now := time.Date(2026, 4, 6, 8, 0, 0, 0, time.Local)
				Expect(s.IsActive(now)).Should(BeFalse())
			})

			It("should not be active after the range", func() {
				// Monday at 18:00
				now := time.Date(2026, 4, 6, 18, 0, 0, 0, time.Local)
				Expect(s.IsActive(now)).Should(BeFalse())
			})

			It("should not be active on a non-matching day", func() {
				// Thursday at 12:00
				now := time.Date(2026, 4, 9, 12, 0, 0, 0, time.Local)
				Expect(now.Weekday()).Should(Equal(time.Thursday))
				Expect(s.IsActive(now)).Should(BeFalse())
			})
		})

		When("overnight range (22:00 - 07:00)", func() {
			var s Schedule
			BeforeEach(func() {
				s = Schedule{
					Start:    "22:00",
					End:      "07:00",
					Weekdays: []Weekday{Weekday(time.Monday), Weekday(time.Friday)},
				}
			})

			It("should be active in the evening on a matching day", func() {
				// Monday at 23:00
				now := time.Date(2026, 4, 6, 23, 0, 0, 0, time.Local)
				Expect(now.Weekday()).Should(Equal(time.Monday))
				Expect(s.IsActive(now)).Should(BeTrue())
			})

			It("should be active in the morning after a matching night", func() {
				// Tuesday at 03:00 (Monday night continues into Tuesday morning)
				now := time.Date(2026, 4, 7, 3, 0, 0, 0, time.Local)
				Expect(now.Weekday()).Should(Equal(time.Tuesday))
				Expect(s.IsActive(now)).Should(BeTrue())
			})

			It("should not be active during the day on a matching day", func() {
				// Monday at 12:00
				now := time.Date(2026, 4, 6, 12, 0, 0, 0, time.Local)
				Expect(s.IsActive(now)).Should(BeFalse())
			})

			It("should not be active on a non-matching day", func() {
				// Wednesday at 23:00
				now := time.Date(2026, 4, 8, 23, 0, 0, 0, time.Local)
				Expect(now.Weekday()).Should(Equal(time.Wednesday))
				Expect(s.IsActive(now)).Should(BeFalse())
			})

			It("should not be active in the morning after a non-matching night", func() {
				// Thursday at 03:00 (Wednesday night, not scheduled)
				now := time.Date(2026, 4, 9, 3, 0, 0, 0, time.Local)
				Expect(now.Weekday()).Should(Equal(time.Thursday))
				Expect(s.IsActive(now)).Should(BeFalse())
			})
		})

		When("range is 00:00 - 00:00", func() {
			var s Schedule
			BeforeEach(func() {
				s = Schedule{
					Start:    "00:00",
					End:      "00:00",
					Weekdays: []Weekday{Weekday(time.Monday)},
				}
			})

			It("should be active for the full day on a matching weekday", func() {
				// Monday at 12:00
				now := time.Date(2026, 4, 6, 12, 0, 0, 0, time.Local)
				Expect(now.Weekday()).Should(Equal(time.Monday))
				Expect(s.IsActive(now)).Should(BeTrue())
			})

			It("should not be active on a non-matching weekday", func() {
				// Tuesday at 12:00
				now := time.Date(2026, 4, 7, 12, 0, 0, 0, time.Local)
				Expect(now.Weekday()).Should(Equal(time.Tuesday))
				Expect(s.IsActive(now)).Should(BeFalse())
			})
		})
	})

	Describe("Blocking validate with schedules", func() {
		It("should accept valid schedule references", func() {
			cfg := Blocking{
				Denylists: map[string][]BytesSource{
					"ads": NewBytesSources("/a/file"),
				},
				Schedules: map[string]Schedule{
					"night": {Start: "22:00", End: "07:00", Weekdays: []Weekday{Weekday(time.Monday)}},
				},
				ClientGroupsBlock: map[string][]string{
					"default": {"ads"},
				},
				ListSchedules: map[string]string{
					"ads": "night",
				},
			}
			Expect(cfg.validate()).Should(Succeed())
		})

		It("should reject undefined schedule references", func() {
			cfg := Blocking{
				Denylists: map[string][]BytesSource{
					"ads": NewBytesSources("/a/file"),
				},
				ClientGroupsBlock: map[string][]string{
					"default": {"ads"},
				},
				ListSchedules: map[string]string{
					"ads": "nonexistent",
				},
			}
			err := cfg.validate()
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("references undefined schedule"))
		})

		It("should reject invalid schedule definitions", func() {
			cfg := Blocking{
				Denylists: map[string][]BytesSource{
					"ads": NewBytesSources("/a/file"),
				},
				Schedules: map[string]Schedule{
					"bad": {Start: "25:00", End: "07:00", Weekdays: []Weekday{Weekday(time.Monday)}},
				},
				ClientGroupsBlock: map[string][]string{
					"default": {"ads"},
				},
				ListSchedules: map[string]string{
					"ads": "bad",
				},
			}
			err := cfg.validate()
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("schedule 'bad'"))
		})
	})
})
