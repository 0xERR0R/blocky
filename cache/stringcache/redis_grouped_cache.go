package stringcache

import (
	"context"
	"time"

	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/redis"
	"github.com/hako/durafmt"
	"github.com/rueian/rueidis"
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

func (r *RedisGroupedStringCache) Refresh(group string) GroupFactory {
	f := &RedisGroupFactory{
		rdb:       r.rdb,
		name:      group,
		cmds:      rueidis.Commands{},
		groupType: r.groupType,
	}

	f.cmds = append(f.cmds,
		r.rdb.Client.B().Del().Key(f.groupKey()).Build(),
		r.rdb.Client.B().Del().Key(r.groupKey(group)).Build())

	return f
}

type RedisGroupFactory struct {
	rdb       *redis.Client
	name      string
	groupType string
	cmds      rueidis.Commands
	cnt       int
}

func (r *RedisGroupFactory) AddEntry(entry string) {
	r.cmds = append(r.cmds,
		r.rdb.Client.B().Sadd().Key(r.groupKey()).Member(entry).Build())
	r.cnt++
}

func (r *RedisGroupFactory) Count() int {
	return r.cnt
}

func (r *RedisGroupFactory) Finish(ctx context.Context) {
	_ = r.rdb.DoMulti(ctx, r.cmds)
}

func (r *RedisGroupFactory) groupKey() string {
	return r.rdb.Keys.Lists.NewSubkey(r.groupType, r.name).String()
}
