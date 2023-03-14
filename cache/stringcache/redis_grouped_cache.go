package stringcache

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
)

type RedisGroupedStringCache struct {
	rdb  *redis.Client
	name string
}

func NewRedisGroupedStringCache(name string) *RedisGroupedStringCache {
	return &RedisGroupedStringCache{
		name: name,
		rdb: redis.NewClient(&redis.Options{
			Addr:     "localhost:6379",
			Password: "", // no password set
			DB:       0,  // use default DB
		}),
	}
}

func (r *RedisGroupedStringCache) cacheKey(groupName string) string {
	return fmt.Sprintf("cache_%s_%s", r.name, groupName)
}

func (r *RedisGroupedStringCache) ElementCount(group string) int {
	return int(r.rdb.SCard(context.Background(), r.cacheKey(group)).Val())
}

func (r *RedisGroupedStringCache) Contains(searchString string, groups []string) []string {
	cmds, err := r.rdb.Pipelined(context.Background(), func(pipeline redis.Pipeliner) error {
		for _, group := range groups {
			pipeline.SIsMember(context.Background(), r.cacheKey(group), searchString)
		}

		return nil
	})
	if err != nil {
		panic(err)
	}

	var result []string

	for ix, group := range groups {
		if cmds[ix].(*redis.BoolCmd).Val() {
			result = append(result, group)
		}
	}

	return result
}

func (r *RedisGroupedStringCache) Refresh(group string) GroupFactory {
	pipeline := r.rdb.Pipeline()
	pipeline.Del(context.Background(), r.cacheKey(group))

	f := &RedisGroupFactory{
		rdb:      r.rdb,
		name:     r.cacheKey(group),
		pipeline: pipeline,
	}

	return f
}

type RedisGroupFactory struct {
	rdb      *redis.Client
	name     string
	pipeline redis.Pipeliner
	cnt      int
}

func (r *RedisGroupFactory) AddEntry(entry string) {
	err := r.pipeline.SAdd(context.Background(), r.name, entry).Err()
	if err != nil {
		panic(err)
	}

	r.cnt++
}

func (r *RedisGroupFactory) Count() int {
	return r.cnt
}

func (r *RedisGroupFactory) Finish() {
	_, err := r.pipeline.Exec(context.Background())
	if err != nil {
		panic(err)
	}
}
