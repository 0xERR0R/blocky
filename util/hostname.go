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

func Hostname() (string, error) {
	return hostname, hostnameErr
}

func getHostname(location string) {
	hostname, hostnameErr = os.Hostname()

	if hn, err := os.ReadFile(location); err == nil {
		hostname = strings.TrimSpace(string(hn))
		hostnameErr = nil

		return
	}
}
