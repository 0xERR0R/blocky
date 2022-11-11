//go:build linux
// +build linux

package main

import (
	"os"
	"time"
	_ "time/tzdata"

	reaper "github.com/ramr/go-reaper"
)

//nolint:gochecknoinits
func init() {
	go reaper.Reap()

	setLocaltime()
}

// set localtime to /etc/localtime if available
// or modify the system time with the TZ environment variable if it is provided
func setLocaltime() {
	// load /etc/localtime without modifying it
	if lt, err := os.ReadFile("/etc/localtime"); err == nil {
		if t, err := time.LoadLocationFromTZData("", lt); err == nil {
			time.Local = t

			return
		}
	}

	// use zoneinfo from time/tzdata and set location with the TZ environment variable
	if tz := os.Getenv("TZ"); tz != "" {
		if t, err := time.LoadLocation(tz); err == nil {
			time.Local = t

			return
		}
	}
}
