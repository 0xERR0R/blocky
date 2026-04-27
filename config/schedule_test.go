package config

import (
	"time"

	"github.com/0xERR0R/blocky/log"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
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

	Describe("parseTimeOfDay", func() {
		It("should parse valid HH:MM times", func() {
			h, m, err := parseTimeOfDay("09:00")
			Expect(err).Should(Succeed())
			Expect(h).Should(Equal(9))
			Expect(m).Should(Equal(0))

			h, m, err = parseTimeOfDay("23:59")
			Expect(err).Should(Succeed())
			Expect(h).Should(Equal(23))
			Expect(m).Should(Equal(59))

			h, m, err = parseTimeOfDay("00:00")
			Expect(err).Should(Succeed())
			Expect(h).Should(Equal(0))
			Expect(m).Should(Equal(0))
		})

		It("should reject non-padded times", func() {
			_, _, err := parseTimeOfDay("8:00")
			Expect(err).Should(HaveOccurred())

			_, _, err = parseTimeOfDay("08:0")
			Expect(err).Should(HaveOccurred())
		})

		It("should reject trailing characters", func() {
			_, _, err := parseTimeOfDay("08:00abc")
			Expect(err).Should(HaveOccurred())
		})

		It("should reject out-of-range values", func() {
			_, _, err := parseTimeOfDay("25:00")
			Expect(err).Should(HaveOccurred())

			_, _, err = parseTimeOfDay("12:60")
			Expect(err).Should(HaveOccurred())
		})

		It("should reject empty and garbage input", func() {
			_, _, err := parseTimeOfDay("")
			Expect(err).Should(HaveOccurred())

			_, _, err = parseTimeOfDay("not-a-time")
			Expect(err).Should(HaveOccurred())
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

		It("should accept omitted start and end (full day)", func() {
			s := Schedule{
				Weekdays: []Weekday{Weekday(time.Monday)},
			}
			Expect(s.validate()).Should(Succeed())
		})

		It("should reject start without end", func() {
			s := Schedule{
				Start:    "22:00",
				Weekdays: []Weekday{Weekday(time.Monday)},
			}
			Expect(s.validate()).Should(MatchError(ContainSubstring("both start and end must be set, or both omitted")))
		})

		It("should reject end without start", func() {
			s := Schedule{
				End:      "07:00",
				Weekdays: []Weekday{Weekday(time.Monday)},
			}
			Expect(s.validate()).Should(MatchError(ContainSubstring("both start and end must be set, or both omitted")))
		})

		It("should reject missing weekdays", func() {
			s := Schedule{
				Start: "22:00",
				End:   "07:00",
			}
			Expect(s.validate()).Should(MatchError(ContainSubstring("weekdays are required")))
		})

		It("should reject invalid start time format", func() {
			s := Schedule{
				Start:    "25:00",
				End:      "07:00",
				Weekdays: []Weekday{Weekday(time.Monday)},
			}
			Expect(s.validate()).Should(HaveOccurred())
		})

		It("should reject invalid end time format", func() {
			s := Schedule{
				Start:    "09:00",
				End:      "25:00",
				Weekdays: []Weekday{Weekday(time.Monday)},
			}
			Expect(s.validate()).Should(HaveOccurred())
		})

		It("should warn about duplicate weekdays", func() {
			testHook := &test.Hook{}
			log.Log().AddHook(testHook)
			log.Log().SetLevel(logrus.WarnLevel)

			defer func() {
				testHook.Reset()
			}()

			s := Schedule{
				Start:    "09:00",
				End:      "17:00",
				Weekdays: []Weekday{Weekday(time.Monday), Weekday(time.Monday), Weekday(time.Monday)},
			}
			Expect(s.validate()).Should(Succeed())
			Expect(testHook.Entries).Should(HaveLen(2))
			Expect(testHook.Entries[0].Message).Should(ContainSubstring("duplicate weekday"))
			Expect(testHook.Entries[0].Message).Should(ContainSubstring("Monday"))
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

			It("should be active at exactly the start time", func() {
				// Monday at 09:00
				now := time.Date(2026, 4, 6, 9, 0, 0, 0, time.Local)
				Expect(s.IsActive(now)).Should(BeTrue())
			})

			It("should not be active at exactly the end time", func() {
				// Monday at 17:00
				now := time.Date(2026, 4, 6, 17, 0, 0, 0, time.Local)
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

			It("should be active at exactly the start time", func() {
				// Monday at 22:00
				now := time.Date(2026, 4, 6, 22, 0, 0, 0, time.Local)
				Expect(now.Weekday()).Should(Equal(time.Monday))
				Expect(s.IsActive(now)).Should(BeTrue())
			})

			It("should not be active at exactly the end time", func() {
				// Tuesday at 07:00 (Monday night's end)
				now := time.Date(2026, 4, 7, 7, 0, 0, 0, time.Local)
				Expect(now.Weekday()).Should(Equal(time.Tuesday))
				Expect(s.IsActive(now)).Should(BeFalse())
			})
		})

		When("range is 00:00 - 00:00 (zero-length window)", func() {
			var s Schedule
			BeforeEach(func() {
				s = Schedule{
					Start:    "00:00",
					End:      "00:00",
					Weekdays: []Weekday{Weekday(time.Monday)},
				}
			})

			It("should never be active (zero-length window)", func() {
				// Monday at 12:00
				now := time.Date(2026, 4, 6, 12, 0, 0, 0, time.Local)
				Expect(now.Weekday()).Should(Equal(time.Monday))
				Expect(s.IsActive(now)).Should(BeFalse())
			})

			It("should not be active at midnight on a matching weekday", func() {
				// Monday at 00:00
				now := time.Date(2026, 4, 6, 0, 0, 0, 0, time.Local)
				Expect(now.Weekday()).Should(Equal(time.Monday))
				Expect(s.IsActive(now)).Should(BeFalse())
			})
		})

		When("start and end are omitted (full day)", func() {
			var s Schedule
			BeforeEach(func() {
				s = Schedule{
					Weekdays: []Weekday{Weekday(time.Monday), Weekday(time.Saturday)},
				}
			})

			It("should be active all day on a matching weekday", func() {
				// Monday at 12:00
				now := time.Date(2026, 4, 6, 12, 0, 0, 0, time.Local)
				Expect(now.Weekday()).Should(Equal(time.Monday))
				Expect(s.IsActive(now)).Should(BeTrue())
			})

			It("should be active at midnight on a matching weekday", func() {
				// Monday at 00:00
				now := time.Date(2026, 4, 6, 0, 0, 0, 0, time.Local)
				Expect(s.IsActive(now)).Should(BeTrue())
			})

			It("should be active at 23:59 on a matching weekday", func() {
				// Saturday at 23:59
				now := time.Date(2026, 4, 11, 23, 59, 0, 0, time.Local)
				Expect(now.Weekday()).Should(Equal(time.Saturday))
				Expect(s.IsActive(now)).Should(BeTrue())
			})

			It("should not be active on a non-matching weekday", func() {
				// Wednesday at 12:00
				now := time.Date(2026, 4, 8, 12, 0, 0, 0, time.Local)
				Expect(now.Weekday()).Should(Equal(time.Wednesday))
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
				ListSchedules: map[string][]string{
					"ads": {"night"},
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
				ListSchedules: map[string][]string{
					"ads": {"nonexistent"},
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
				ListSchedules: map[string][]string{
					"ads": {"bad"},
				},
			}
			err := cfg.validate()
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("schedule 'bad'"))
		})

		It("should accept multiple schedules for one list", func() {
			cfg := Blocking{
				Denylists: map[string][]BytesSource{
					"ads": NewBytesSources("/a/file"),
				},
				Schedules: map[string]Schedule{
					"night":   {Start: "22:00", End: "07:00", Weekdays: []Weekday{Weekday(time.Monday)}},
					"weekend": {Weekdays: []Weekday{Weekday(time.Saturday), Weekday(time.Sunday)}},
				},
				ClientGroupsBlock: map[string][]string{
					"default": {"ads"},
				},
				ListSchedules: map[string][]string{
					"ads": {"night", "weekend"},
				},
			}
			Expect(cfg.validate()).Should(Succeed())
		})

		It("should reject listSchedules referencing undefined list", func() {
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
				ListSchedules: map[string][]string{
					"nonexistent-list": {"night"},
				},
			}
			err := cfg.validate()
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("references undefined list"))
		})
	})
})
