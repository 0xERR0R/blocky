package instanceid

import (
	"bytes"

	"github.com/google/uuid"
)

// nolint:gochecknoglobals
var instanceID uuid.UUID

// nolint:gochecknoinits
func init() {
	instanceID = uuid.New()
}

// String instanceid representation as string
func String() string {
	return instanceID.String()
}

// Bytes instanceid representation as slice of bytes
func Bytes() []byte {
	b, _ := instanceID.MarshalBinary()
	return b
}

// Equal compares a slice of bytes to the InstanceId
func Equal(comp []byte) bool {
	return bytes.Equal(comp, Bytes())
}
