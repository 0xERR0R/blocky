package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/0xERR0R/blocky/log"
	"github.com/rueian/rueidis"
	"github.com/rueian/rueidis/rueidislock"
	"github.com/sirupsen/logrus"
)

// Ticker is a redis key expiration based ticker
type Ticker struct {
	lockerName string
	key        *Key
	duration   TTL
	client     rueidis.Client
	locker     rueidislock.Locker
	ctxCa      context.CancelFunc
	c          chan time.Time
	l          *logrus.Entry
}

// internal constructor
func newTicker(d TTL, name string, bk *Key, client rueidis.Client, locker rueidislock.Locker) (*Ticker, error) {
	if d.SecondsUI32() == 0 {
		return nil, errors.New("the ticker duration hast to be at least one second")
	}

	ctx, ctxCa := context.WithCancel(context.Background())

	res := Ticker{
		lockerName: fmt.Sprintf("ticker-%s", name),
		key:        bk.NewSubkey(name),
		duration:   d,
		client:     client,
		locker:     locker,
		ctxCa:      ctxCa,
		c:          make(chan time.Time, 1),
		l:          log.PrefixedLog(fmt.Sprintf("%s-tricker", name)),
	}

	if err := enableExpiredNKE(ctx, client); err != nil {
		res.Stop()

		return nil, err
	}

	go func() {
		dClient, dcCancel := client.Dedicate()
		defer dcCancel()

		_ = dClient.Receive(ctx,
			dClient.B().Psubscribe().Pattern(res.key.KeySpacePattern()).Build(),
			func(m rueidis.PubSubMessage) {
				res.c <- time.Now()
				res.set(ctx)
			})
	}()

	if !res.exists(ctx) {
		res.set(ctx)
	}

	return &res, nil
}

// Resets the ticker to a new duration
func (t *Ticker) Reset(d time.Duration) {
	t.duration = TTL(d)

	t.set(context.Background())
}

// Stop closes the ticker
func (t *Ticker) Stop() {
	defer t.ctxCa()
	defer close(t.c)
}

// C is the ticker channel
func (t *Ticker) C() <-chan time.Time {
	return t.c
}

// checks if key exists
func (t *Ticker) exists(ctx context.Context) bool {
	lctx, lcancel, err := t.locker.WithContext(ctx, t.lockerName)
	if err != nil {
		t.l.Debug(err)

		return false
	}

	defer lcancel()

	res, err := t.client.Do(lctx,
		t.client.B().
			Exists().
			Key(t.key.String()).
			Build()).AsBool()
	if err != nil {
		return false
	}

	return res
}

// set ttl to ticker key
func (t *Ticker) set(ctx context.Context) {
	lctx, lcancel, err := t.locker.TryWithContext(ctx, t.lockerName)
	if err != nil {
		t.l.Debug(err)

		return
	}

	defer lcancel()

	res := t.client.Do(lctx,
		t.client.B().Set().
			Key(t.key.String()).
			Value(t.duration.String()).
			ExSeconds(t.duration.SecondsI64()).
			Build())

	if res.Error() != nil {
		t.l.Error(res.Error())
	}
}
