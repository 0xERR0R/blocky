package redis

import (
	"fmt"
	"strings"
	gotime "time"

	"golang.org/x/exp/constraints"
)

const (
	second TTL = 10000000
)

// A TTL is used for conversion of redis key experations.
// The duration is stored identically to time.Duration.
type TTL int64

// Duration converts the TTL to time.Duration
func (ttl TTL) Duration() gotime.Duration {
	return gotime.Duration(ttl)
}

// String is a shortcut to Duration().String()
func (ttl TTL) String() string {
	return ttl.Duration().String()
}

// SecondsI64 returns the TTL seconds as int64
func (ttl TTL) SecondsI64() int64 {
	return int64(ttl / second)
}

// SecondsUI32 returns the TTL seconds as uint32
func (ttl TTL) SecondsUI32() uint32 {
	return uint32(ttl / second)
}

// SecondsToTTL converts seconds stored in an integer type to TTL
func SecondsToTTL[T constraints.Integer](seconds T) TTL {
	return second * TTL(seconds)
}

// Key represents a redis key
type Key struct {
	completeKey  string
	key          string
	database     int
	spacePattern string
}

// Key constructor
func newKey(database int, parts ...string) *Key {
	res := Key{
		completeKey: strings.Join(parts, ":"),
		key:         parts[len(parts)-1],
		database:    database,
	}

	res.spacePattern = fmt.Sprintf("__keyspace@%d__:%s", res.database, res.completeKey)

	return &res
}

// String representation of the complete key
func (k *Key) String() string {
	return k.completeKey
}

// Key representation the last of the key
func (k *Key) Key() string {
	return k.key
}

// KeySpacePattern is used for pub/sub subscription
func (k *Key) KeySpacePattern() string {
	return k.spacePattern
}

// NewSubkey creates a new key with the current key as parent
func (k *Key) NewSubkey(parts ...string) *Key {
	ip := []string{k.completeKey}

	ip = append(ip, parts...)

	return newKey(k.database, ip...)
}
