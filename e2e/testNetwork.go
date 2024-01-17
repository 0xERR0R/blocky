package e2e

import (
	"fmt"
	"sync/atomic"
	"time"
)

// testNetwork is a helper struct to create a unique network name and count the number of attached containers.
type testNetwork struct {
	name    atomic.Value
	counter atomic.Int32
}

// Name returns the name of the test network.
func (n *testNetwork) Name() string {
	if v := n.name.Load(); v != nil {
		return v.(string)
	}

	n.Reset()

	return n.Name()
}

// Reset generates a new network name.
func (n *testNetwork) Reset() {
	n.name.Store(fmt.Sprintf("blocky-e2e-network_%d", time.Now().Unix()))
}

// Attach increments the network counter.
func (n *testNetwork) Attach() {
	n.counter.Add(1)
}

// Detach decrements the network counter and returns true if the counter hits zero which indicates that the
// network can be removed.
func (n *testNetwork) Detach() bool {
	if n.counter.Load() <= 0 {
		return false
	}

	n.counter.Add(-1)

	if n.counter.Load() == 0 {
		n.Reset()

		return true
	}

	return false
}
