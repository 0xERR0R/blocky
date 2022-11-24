package util

import (
	"os"
	"strings"
)

//nolint:gochecknoglobals
var (
	hostname    string
	hostnameErr error
)

const hostnameFile string = "/etc/hostname"

//nolint:gochecknoinits
func init() {
	getHostname(hostnameFile)
}

// Direct replacement for os.Hostname
func Hostname() (string, error) {
	return hostname, hostnameErr
}

// Only return the hostname(may be empty if there was an error)
func HostnameString() string {
	return hostname
}

func getHostname(location string) {
	hostname, hostnameErr = os.Hostname()

	if hn, err := os.ReadFile(location); err == nil {
		hostname = strings.TrimSpace(string(hn))
		hostnameErr = nil

		return
	}
}
