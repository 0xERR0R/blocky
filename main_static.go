//go:build linux

package main

import (
	_ "time/tzdata"

	_ "github.com/breml/rootcerts"

	reaper "github.com/ramr/go-reaper"
)

//nolint:gochecknoinits
func init() {
	go reaper.Reap()
}
