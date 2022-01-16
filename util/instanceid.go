package util

import (
	"bytes"
	"fmt"

	"github.com/google/uuid"
)

// ID type for InstanceId with base slice of bytes
type ID []byte

// nolint:gochecknoglobals
var (
	InstanceId ID
)

// nolint:gochecknoinits
func init() {
	id, err := uuid.New().MarshalBinary()
	if err != nil {
		panic(err)
	} else if id == nil {
		panic(fmt.Errorf("InstanceId is nil"))
	} else {
		InstanceId = ID(id)
	}
}

// String InstanceId representation as string
func (i ID) String() string {
	return string(i)
}

// Bytes InstanceId representation as slice of bytes
func (i ID) Bytes() []byte {
	return i
}

// Equal compares a slice of bytes to the InstanceId
func (i ID) Equal(comp []byte) bool {
	return bytes.Equal(comp, i)
}
