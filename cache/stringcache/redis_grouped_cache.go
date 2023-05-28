package stringcache

import (
	"context"
	"sync"
	"time"

	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/redis"
	"github.com/hako/durafmt"
	"github.com/rueian/rueidis"
)

const (
	workSubKey = "in_progress"
	numWorkers = 10
	chunkSize  = 100000
)

type RedisGroupedStringCache struct {
	rdb       *redis.Client
	groupType string
}

func NewRedisGroupedStringCache(groupType string, rdb *redis.Client) *RedisGroupedStringCache {
	return &RedisGroupedStringCache{
		groupType: groupType,
		rdb:       rdb,
	}
}

func (r *RedisGroupedStringCache) groupKey(groupName string) string {
	return r.rdb.Keys.Lists.NewSubkey(r.groupType, groupName).String()
}

func (r *RedisGroupedStringCache) ElementCount(group string) int {
	res, err := r.rdb.Client.DoCache(context.Background(),
		r.rdb.Client.B().Scard().Key(r.groupKey(group)).Cache(),
		r.rdb.LocalCacheTime.Duration()).ToInt64()
	if err != nil {
		return 0
	}

	return int(res)
}

func (r *RedisGroupedStringCache) Contains(searchString string, groups []string) []string {
	start := time.Now()

	var result []string

	for _, group := range groups {
		res, err := r.rdb.Client.DoCache(context.Background(),
			r.rdb.Client.B().Sismember().Key(r.groupKey(group)).Member(searchString).Cache(),
			r.rdb.LocalCacheTime.Duration()).AsBool()
		if err != nil {
			panic(err)
		}

		if res {
			result = append(result, group)
		}
	}

	log.PrefixedLog("redis").Debugf("lookup for '%s': in groups: %v result: %v, duration %s",
		searchString, groups, result, durafmt.Parse(time.Since(start)).String())

	return result
}

func (r *RedisGroupedStringCache) Refresh(ctx context.Context, group string) GroupFactory {
	f := &RedisGroupFactory{
		rdb:       r.rdb,
		name:      group,
		cmds:      make(chan rueidis.Commands),
		groupType: r.groupType,
		key:       r.rdb.Keys.Lists.NewSubkey(r.groupType, group).String(),
		workKey:   r.rdb.Keys.Lists.NewSubkey(r.groupType, workSubKey, group).String(),
		ctx:       ctx,
		cnt:       0,
		wg:        sync.WaitGroup{},
	}

	f.rdb.Client.Do(f.ctx,
		f.rdb.Client.B().Del().Key(f.workKey).Build())

	f.startWorker()

	return f
}

type RedisGroupFactory struct {
	rdb       *redis.Client
	name      string
	groupType string
	cnt       int
	key       string
	workKey   string
	ctx       context.Context
	cmds      chan rueidis.Commands
	wg        sync.WaitGroup
}

func (r *RedisGroupFactory) AddEntry(entry string) {
	r.cmds <- rueidis.Commands{r.rdb.Client.B().Sadd().Key(r.workKey).Member(entry).Build()}
	r.cnt++
}

func (r *RedisGroupFactory) Count() int {
	return r.cnt
}

func (r *RedisGroupFactory) Finish() {
	close(r.cmds)

	r.wg.Wait()

	_ = r.rdb.Client.Do(r.ctx,
		r.rdb.Client.B().Rename().Key(r.workKey).Newkey(r.key).Build())
}

func (r *RedisGroupFactory) startWorker() {
	r.wg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		go r.worker()
	}
}

func (r *RedisGroupFactory) worker() {
	defer r.wg.Done()
	wcmds := rueidis.Commands{}
	for {
		select {
		case <-r.ctx.Done():
			return
		case cmd, ok := <-r.cmds:
			wcmds = append(wcmds, cmd...)
			if len(wcmds) >= chunkSize {
				_ = r.rdb.Client.DoMulti(r.ctx, wcmds...)
				wcmds = rueidis.Commands{}
			}

			if !ok {
				if len(wcmds) > 0 {
					_ = r.rdb.Client.DoMulti(r.ctx, wcmds...)
				}
				for cmd2 := range r.cmds {
					wcmds = append(wcmds, cmd2...)
					if len(wcmds) >= chunkSize {
						_ = r.rdb.Client.DoMulti(r.ctx, wcmds...)
						wcmds = rueidis.Commands{}
					}
				}
				return
			}
		}
	}
}
