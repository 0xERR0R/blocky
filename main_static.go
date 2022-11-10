//go:build linux
// +build linux

package main

import (
	"fmt"
	"os"
	"time"
	_ "time/tzdata"

	reaper "github.com/ramr/go-reaper"
)

//nolint:gochecknoinits
func init() {
	go reaper.Reap()

	if tz := os.Getenv("TZ"); tz != "" {
		var err error
		time.Local, err = time.LoadLocation(tz)

		if err != nil {
			fmt.Printf("error loading location '%s': %v\n", tz, err)
		}
	}
}
