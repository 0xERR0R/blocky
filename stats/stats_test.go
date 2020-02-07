package stats

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_Put_ExeedsMax(t *testing.T) {
	mockTime := "20200101_0101"
	now = func() time.Time {
		t, _ := time.Parse("20060102_1505", mockTime)
		return t
	}
	s := NewAggregatorWithMax("test", 3)

	s.Put("a2")
	s.Put("a1")
	s.Put("a2")
	s.Put("a3")
	s.Put("a1")
	s.Put("a1")
	s.Put("a4")
	s.Put("a5")
	s.Put("a2")
	s.Put("a6")
	s.Put("a1")
	s.Put("a6")
	s.Put("a1")

	// change hour
	mockTime = "20200101_0201"

	s.Put("a1")
	res := s.AggregateResult()

	assert.Len(t, res, 3)
	assert.Equal(t, 5, res["a1"])
	assert.Equal(t, 3, res["a2"])
	assert.Equal(t, 2, res["a6"])
}

func Test_Put_AggregateMultipleHours(t *testing.T) {
	mockTime := "20200102_0101"
	now = func() time.Time {
		t, _ := time.Parse("20060102_1505", mockTime)
		return t
	}
	s := NewAggregatorWithMax("test", 3)

	s.Put("a2")
	s.Put("a1")
	s.Put("a2")
	s.Put("a3")
	s.Put("a1")
	s.Put("a1")
	s.Put("a4")
	s.Put("a5")
	s.Put("a2")
	s.Put("a6")
	s.Put("a1")
	s.Put("a6")
	s.Put("a1")

	// change hour
	mockTime = "20200102_0201"

	s.Put("a1")

	// change hour
	mockTime = "20200102_0301"

	s.Put("a2")
	s.Put("a1")

	// change hour
	mockTime = "20200102_0401"

	res := s.AggregateResult()

	assert.Len(t, res, 3)
	assert.Equal(t, 7, res["a1"])
	assert.Equal(t, 4, res["a2"])
	assert.Equal(t, 2, res["a6"])
}

func Test_Put_AggregateMultipleHoursOver24h(t *testing.T) {
	mockTime := "20200103_0101"
	now = func() time.Time {
		t, _ := time.Parse("20060102_1505", mockTime)
		return t
	}
	s := NewAggregatorWithMax("test", 3)

	s.Put("a1")
	s.Put("a2")

	// change hour
	mockTime = "20200103_0201"

	s.Put("a2")
	s.Put("a3")

	// change hour
	mockTime = "20200103_0301"

	s.Put("a3")
	s.Put("a4")
	s.Put("a5")

	// change day
	mockTime = "20200104_0101"

	res := s.AggregateResult()

	assert.Len(t, res, 3)
	assert.Equal(t, 2, res["a3"])
	assert.Equal(t, 1, res["a4"])
	assert.Equal(t, 1, res["a5"])
}

func Test_Put_UnderMax(t *testing.T) {
	mockTime := "20200105_0101"
	now = func() time.Time {
		t, _ := time.Parse("20060102_1505", mockTime)
		return t
	}
	s := NewAggregator("test")

	s.Put("a2")
	s.Put("a1")
	s.Put("a2")
	s.Put("a3")
	s.Put("a2")
	s.Put("a2")
	s.Put("a2")

	// change hour
	mockTime = "20200105_0201"

	s.Put("a1")

	res := s.AggregateResult()

	assert.Len(t, res, 3)
	assert.Equal(t, 1, res["a1"])
	assert.Equal(t, 5, res["a2"])
	assert.Equal(t, 1, res["a3"])
}

func Test_Put_Empty(t *testing.T) {
	mockTime := "20200104_0101"
	now = func() time.Time {
		t, _ := time.Parse("20060102_1505", mockTime)
		return t
	}
	s := NewAggregator("test")

	s.Put("")
	s.Put("a1")

	// change hour
	mockTime = "20200104_0201"

	res := s.AggregateResult()

	assert.Len(t, res, 1)
}
