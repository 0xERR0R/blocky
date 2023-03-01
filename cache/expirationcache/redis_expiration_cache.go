package expirationcache

import (
	"context"
	"fmt"
	"github.com/go-redis/redis/v8"
	"github.com/miekg/dns"
	"strconv"
	"time"
)

type RedisCache struct {
	rdb  *redis.Client
	name string
}

func (r *RedisCache) Put(key string, val interface{}, expiration time.Duration) {
	switch v := val.(type) {
	case dns.Msg:
		b, err := v.Pack()
		if err != nil {
			panic(err)
		}
		err = r.rdb.Set(context.Background(), r.name+":"+key, b, expiration).Err()
		if err != nil {
			panic(err)
		}
	case int:
		err := r.rdb.Set(context.Background(), r.name+":"+key, v, expiration).Err()
		if err != nil {
			panic(err)
		}
	default:
		fmt.Println("type unknown")
	}

}

func (r *RedisCache) Get(key string) (val interface{}, expiration time.Duration) {
	bytesVal, err := r.rdb.Get(context.Background(), r.name+":"+key).Bytes()
	if err == redis.Nil {
		return nil, 0
	}
	if err != nil {
		panic(err)
	}

	exp := r.rdb.TTL(context.Background(), r.name+":"+key).Val()

	if len(bytesVal) <= 2 {
		code, err := strconv.Atoi(string(bytesVal))
		if err != nil {
			panic(err)
		}
		return code, exp
	}

	msg := new(dns.Msg)
	err = msg.Unpack(bytesVal)
	if err != nil {
		panic(err)
	}

	return msg, exp
}

func (r *RedisCache) TotalCount() int {
	//TODO implement me
	return 0
}

func (r *RedisCache) Clear() {
	//TODO implement me

}

func NewRedisCache(rdb *redis.Client, name string) *RedisCache {

	return &RedisCache{
		rdb:  rdb,
		name: name,
	}
}
