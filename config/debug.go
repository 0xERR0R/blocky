// Copyright 2026 Chris Snell
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

// Debug holds the Go diagnostics listener (net/http/pprof and expvar).
//
// It gets its own listener rather than a route group on the HTTP API port
// because RequireAuth only rejects /api/* paths — anything mounted outside
// that prefix is readable without a session (auth/middleware.go). Heap and
// goroutine dumps carry in-flight query names and client addresses, cmdline
// leaks the invocation, and /debug/pprof/profile pins a CPU for the sampling
// duration, so the bind address is loopback and deliberately not configurable.
type Debug struct {
	// Enable the pprof/expvar diagnostics listener on loopback (127.0.0.1 and [::1]).
	Enable bool `default:"false" yaml:"enable"`
	// Port for the diagnostics listener. It only ever binds loopback; reach it from
	// another host with an SSH tunnel or `kubectl port-forward`, not by rebinding it.
	Port uint16 `default:"6060" yaml:"port"`
}

// IsEnabled implements `config.Configurable`.
func (c *Debug) IsEnabled() bool {
	return c.Enable
}

// LogConfig implements `config.Configurable`.
func (c *Debug) LogConfig(logger *logrus.Entry) {
	logger.Infof("listen = %s", strings.Join(c.ListenAddresses(), ", "))
}

// ListenAddresses returns the loopback addresses the diagnostics listener binds,
// one per IP family. A host that lacks one of the two families is normal, so the
// caller requires only one of them to bind successfully.
func (c *Debug) ListenAddresses() []string {
	port := strconv.Itoa(int(c.Port))

	return []string{
		net.JoinHostPort("127.0.0.1", port),
		net.JoinHostPort("::1", port),
	}
}

func (c *Debug) validate() error {
	// Port 0 would have the OS pick, which yields a *different* port per
	// address family and no way to discover either — useless for a listener
	// whose whole purpose is being attached to by hand.
	if c.Enable && c.Port == 0 {
		return errors.New("debug.port must be set when debug.enable is true")
	}

	return nil
}
