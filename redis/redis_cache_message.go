package redis

import (
	"encoding/json"

	"github.com/0xERR0R/blocky/model"
)

// CacheMessage struct holding key and response for cache synchronization
type CacheMessage struct {
	Key      string
	Response *model.Response
}

// MarshalBinary encodes the struct to json
func (u *CacheMessage) MarshalBinary() ([]byte, error) {
	return json.Marshal(u)
}

// UnmarshalBinary decodes the struct into a CacheMessage
func (u *CacheMessage) UnmarshalBinary(data []byte) error {
	err := json.Unmarshal(data, &u)

	return err
}
