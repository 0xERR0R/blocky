//go:build linux
// +build linux

package main

import (
	_ "time/tzdata"

	reaper "github.com/ramr/go-reaper"
)

//nolint:gochecknoinits
func init() {
	go reaper.Reap()
}
