package parsers

import (
	"bufio"
	"bytes"
	"encoding"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/hashicorp/go-multierror"
)

const maxDomainNameLength = 255 // https://www.rfc-editor.org/rfc/rfc1034#section-3.1

var domainNameRegex = regexp.MustCompile(govalidator.DNSName)

// Hosts parses `r` as a series of `HostsIterator`.
// It supports both the hosts file and host list formats.
//
// Each item being an iterator was chosen to abstract the difference between the
// two formats where each host list entry is a single host, but a hosts file
// entry can be multiple due to aliases.
// It also avoids allocating intermediate lists.
func Hosts(r io.Reader) SeriesParser[*HostsIterator] {
	return LinesAs[*HostsIterator](r)
}

type HostsIterator struct {
	hostsIterator
}

type hostsIterator interface {
	encoding.TextUnmarshaler

	forEachHost(callback func(string) error) error
}

func (h *HostsIterator) ForEach(callback func(string) error) error {
	return h.hostsIterator.forEachHost(callback)
}

func (h *HostsIterator) UnmarshalText(data []byte) error {
	var mErr *multierror.Error

	entries := []hostsIterator{
		new(HostListEntry),
		new(HostsFileEntry),
	}

	for _, entry := range entries {
		err := entry.UnmarshalText(data)
		if err != nil {
			mErr = multierror.Append(mErr, err)

			continue
		}

		h.hostsIterator = entry

		return nil
	}

	return multierror.Flatten(mErr)
}

// HostList parses `r` as a series of `HostListEntry`.
//
// This is for the host list format commonly used by ad blockers.
func HostList(r io.Reader) SeriesParser[*HostListEntry] {
	return LinesAs[*HostListEntry](r)
}

// HostListEntry is a single host.
type HostListEntry string

func (e HostListEntry) String() string {
	return string(e)
}

// We assume this is used with `Lines`:
// - data will never be empty
// - comments are stripped
func (e *HostListEntry) UnmarshalText(data []byte) error {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Split(bufio.ScanWords)

	_ = scanner.Scan() // data is not empty

	host := scanner.Text()

	if err := validateHostsListEntry(host); err != nil {
		return err
	}

	if scanner.Scan() {
		return fmt.Errorf("unexpected second column: %s", scanner.Text())
	}

	*e = HostListEntry(host)

	return nil
}

func (e HostListEntry) forEachHost(callback func(string) error) error {
	return callback(e.String())
}

// HostsFile parses `r` as a series of `HostsFileEntry`.
//
// This is for the hosts file format used by OSes, usually `/etc/hosts`.
func HostsFile(r io.Reader) SeriesParser[*HostsFileEntry] {
	return LinesAs[*HostsFileEntry](r)
}

// HostsFileEntry is an entry from an OS hosts file.
type HostsFileEntry struct {
	IP        net.IP
	Interface string
	Name      string
	Aliases   []string
}

// We assume this is used with `Lines`:
// - data will never be empty
// - comments are stripped
func (e *HostsFileEntry) UnmarshalText(data []byte) error {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Split(bufio.ScanWords)

	_ = scanner.Scan() // data is not empty

	ipStr := scanner.Text()

	var netInterface string

	// Remove interface part
	if idx := strings.IndexRune(ipStr, '%'); idx != -1 {
		// if `netInterface` is empty it's technically an invalid entry, but we'll ignore that here
		netInterface = ipStr[idx+1:]
		ipStr = ipStr[:idx]
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid ip: %s", scanner.Text())
	}

	hosts := make([]string, 0, 1) // 1: there must be at least one for the line to be valid

	for scanner.Scan() {
		host := scanner.Text()

		if err := validateDomainName(host); err != nil {
			return err
		}

		hosts = append(hosts, host)
	}

	if len(hosts) == 0 {
		return fmt.Errorf("expected at least one host following IP")
	}

	*e = HostsFileEntry{
		IP:        ip,
		Interface: netInterface,
		Name:      hosts[0],
		Aliases:   hosts[1:],
	}

	return nil
}

func (e HostsFileEntry) forEachHost(callback func(string) error) error {
	err := callback(e.Name)
	if err != nil {
		return err
	}

	for _, alias := range e.Aliases {
		err := callback(alias)
		if err != nil {
			return err
		}
	}

	return nil
}

func validateDomainName(host string) error {
	if len(host) > maxDomainNameLength {
		return fmt.Errorf("domain name is too long: %s", host)
	}

	if domainNameRegex.MatchString(host) {
		return nil
	}

	return fmt.Errorf("invalid domain name: %s", host)
}

func validateHostsListEntry(host string) error {
	if net.ParseIP(host) != nil {
		return nil
	}

	if strings.HasPrefix(host, "/") && strings.HasSuffix(host, "/") {
		_, err := regexp.Compile(host)

		return err
	}

	return validateDomainName(host)
}
