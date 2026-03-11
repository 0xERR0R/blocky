package arp

import (
	"bufio"
	"net"
	"os"
	"strings"
)

// Entry represents a single ARP table entry.
type Entry struct {
	IP     string `json:"ip"`
	MAC    string `json:"mac"`
	Device string `json:"device"`
}

const defaultProcFile = "/proc/net/arp"

// Read parses the Linux ARP table from /proc/net/arp.
// Returns nil (not an error) if the file does not exist (e.g. on macOS).
func Read() ([]Entry, error) {
	return ReadFile(defaultProcFile)
}

// ReadFile parses an ARP table from the given file path.
func ReadFile(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}

		return nil, err
	}
	defer f.Close()

	var entries []Entry

	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header line

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}

		ip := fields[0]
		flags := fields[2]
		mac := fields[3]
		device := fields[5]

		// flags 0x0 means incomplete entry (no MAC resolved yet)
		if flags == "0x0" || mac == "00:00:00:00:00:00" {
			continue
		}

		if net.ParseIP(ip) == nil {
			continue
		}

		entries = append(entries, Entry{
			IP:     ip,
			MAC:    mac,
			Device: device,
		})
	}

	return entries, scanner.Err()
}

// LookupMAC returns the MAC address for the given IP, or empty string if not found.
func LookupMAC(ip string) string {
	entries, err := Read()
	if err != nil || entries == nil {
		return ""
	}

	for _, e := range entries {
		if e.IP == ip {
			return e.MAC
		}
	}

	return ""
}
