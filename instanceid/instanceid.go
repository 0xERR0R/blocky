package instanceid

import (
	"bytes"

	"github.com/google/uuid"
)

// nolint:gochecknoglobals
var instanceId uuid.UUID

// nolint:gochecknoinits
func init() {
	instanceId = uuid.New()
}

// String instanceid representation as string
func String() string {
	return instanceId.String()
}

// Bytes instanceid representation as slice of bytes
func Bytes() []byte {
	b, _ := instanceId.MarshalBinary()
	return b
}

// Equal compares a slice of bytes to the InstanceId
func Equal(comp []byte) bool {
	return bytes.Equal(comp, Bytes())
}
