package model

import "time"

type TickerWrapper interface {
	C() <-chan time.Time
	Reset(d time.Duration)
	Stop()
}

type TimeTicker struct {
	ticker time.Ticker
}

func NewTimeTicker(d time.Duration) *TimeTicker {
	res := &TimeTicker{
		ticker: *time.NewTicker(d),
	}

	return res
}

func (t *TimeTicker) C() <-chan time.Time {
	return t.ticker.C
}

func (t *TimeTicker) Reset(d time.Duration) {
	t.ticker.Reset(d)
}

func (t *TimeTicker) Stop() {
	t.ticker.Stop()
}
