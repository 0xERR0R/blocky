package stats

import (
	"blocky/util"
	"strings"
	"sync"
	"time"
)

const (
	defaultMaxCount = 50
	hours           = 24
)

// nolint
var now = time.Now

// Aggregator cummulates hourly different results
type Aggregator struct {
	// hour -> ( string -> count )
	hourResults map[string]map[string]int
	Name        string
	currentHour string
	maxCount    int
	lock        sync.RWMutex
	stageData   map[string]int
}

// NewAggregator returns new aggregator with specified name
func NewAggregator(name string) *Aggregator {
	return NewAggregatorWithMax(name, defaultMaxCount)
}

// NewAggregatorWithMax returns new aggregator with max count
func NewAggregatorWithMax(name string, maxCount uint) *Aggregator {
	return &Aggregator{
		Name:        name,
		maxCount:    int(maxCount),
		stageData:   make(map[string]int),
		hourResults: make(map[string]map[string]int),
		currentHour: currentHour(),
	}
}

// AggregateResult returns a map with aggregation result
func (s *Aggregator) AggregateResult() map[string]int {
	result := make(map[string]int)

	s.lock.RLock()
	defer s.lock.RUnlock()

	s.hourSwitch()

	for _, hv := range s.hourResults {
		for k, v := range hv {
			if val, ok := result[k]; ok {
				result[k] = val + v
			} else {
				result[k] = v
			}
		}
	}

	return getMaxValues(result, s.maxCount)
}

// returns current date with hour
func currentHour() string {
	return now().Format("2006010215")
}

// Put adds a new key to the aggregation
func (s *Aggregator) Put(key string) {
	key = strings.TrimSpace(key)
	if len(key) > 0 {
		s.lock.Lock()
		defer s.lock.Unlock()

		s.hourSwitch()

		if val, ok := s.stageData[key]; ok {
			s.stageData[key] = val + 1
		} else {
			s.stageData[key] = 1
		}
	}
}

func (s *Aggregator) hourSwitch() {
	hour := currentHour()
	if hour == s.currentHour {
		return
	}

	s.hourResults[s.currentHour] = getMaxValues(s.stageData, s.maxCount*2)

	for k := range s.hourResults {
		h, _ := time.Parse("2006010215", k)

		if h.Before(now().Add(-1 * hours * time.Hour)) {
			delete(s.hourResults, k)
		}
	}

	s.currentHour = hour
	s.stageData = make(map[string]int)
}

func getMaxValues(in map[string]int, maxCount int) map[string]int {
	if len(in) <= maxCount {
		return in
	}

	res := make(map[string]int, maxCount)
	i := 0

	util.IterateValueSorted(in, func(k string, v int) {
		if i < maxCount {
			res[k] = v
		}
		i++
	})

	return res
}
