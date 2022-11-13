package util

import (
	"os"
	"strings"
)

var (
	hostname    string
	hasHostname bool
)

const hostnameFile string = "/etc/hostname"

//nolint:gochecknoinits
func init() {
	getHostname(hostnameFile)
}

func Hostname() (string, bool) {
	return hostname, hasHostname
}

func getHostname(location string) {
	if hn, err := os.ReadFile(location); err == nil {
		hostname = sanitize(string(hn))

		hasHostname = true

		return
	}

	if hn, err := os.Hostname(); err == nil {
		hostname = sanitize(hn)

		hasHostname = true

		return
	}

	hostname = ""
	hasHostname = false
}

func sanitize(orig string) string {
	return strings.ToLower(strings.TrimSpace(orig))
}
