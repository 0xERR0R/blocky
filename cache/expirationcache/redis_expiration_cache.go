package expirationcache

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/rueian/rueidis"
)

type RedisCache struct {
	rdb  rueidis.Client
	name string
}

func Key(k ...string) string {
	return fmt.Sprintf("blocky:%s", strings.Join(k, ":"))
}

func (r *RedisCache) cacheKey(key string) string {
	return Key("cache", r.name, key)
}

func toSeconds(t time.Duration) int64 {
	return int64(t.Seconds())
}

func NoResult(res rueidis.RedisResult) bool {
	err := res.Error()

	return err != nil && rueidis.IsRedisNil(err)
}

func (r *RedisCache) Put(key string, val *dns.Msg, expiration time.Duration) {
	b, err := val.Pack()
	if err != nil {
		panic(err)
	}
	cmd := r.rdb.B().Setex().Key(r.cacheKey(key)).Seconds(toSeconds(expiration)).Value(rueidis.BinaryString(b)).Build()
	r.rdb.Do(context.Background(), cmd).Error()
	if err != nil {
		panic(err)
	}
}

func (r *RedisCache) Get(key string) (val *dns.Msg, expiration time.Duration) {
	cmd := r.rdb.B().Get().Key(r.cacheKey(key)).Cache()
	resp := r.rdb.DoCache(context.Background(), cmd, 600*time.Second)
	if NoResult(resp) {
		return nil, 0
	}
	err := resp.Error()
	if err != nil {
		panic(err)
	}

	respStr, err := resp.ToString()
	if err != nil {
		panic(err)
	}
	bytesVal := []byte(respStr)

	msg := new(dns.Msg)
	err = msg.Unpack(bytesVal)
	if err != nil {
		panic(err)
	}

	return msg, time.Duration(resp.CacheTTL() * int64(time.Second))
}

func (r *RedisCache) TotalCount() int {
	// TODO implement me
	return 0
}

func (r *RedisCache) Clear() {
	// TODO implement me

}

func NewRedisCache(rdb rueidis.Client, name string) ExpiringCache[dns.Msg] {
	return &RedisCache{
		rdb:  rdb,
		name: name,
	}
}
