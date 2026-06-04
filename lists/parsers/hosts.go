package parsers

import (
	"bytes"
	"encoding"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"

	"github.com/hashicorp/go-multierror"
	"golang.org/x/net/idna"
)

const (
	maxDomainNameLength = 255 // https://www.rfc-editor.org/rfc/rfc1034#section-3.1

	dnsLabelPattern = `[a-zA-Z0-9_-]{1,63}`
)

// Validate a domain name, but with extra flexibility:
// - no restriction on the start or end of labels
//
// https://www.rfc-editor.org/rfc/rfc1034#section-3.5
var domainNameRegex = regexp.MustCompile(`^` + dnsLabelPattern + `(\.` + dnsLabelPattern + `)*[\._]?$`)

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
	return h.forEachHost(callback)
}

// hostsEntryParsers tries to parse a line as each supported entry type, in order.
// It is a package-level value so the slice is allocated once, not per line, and
// each entry is only allocated when its parser is actually reached.
var hostsEntryParsers = []func([]byte) (hostsIterator, error){
	func(data []byte) (hostsIterator, error) { e := new(HostListEntry); return e, e.UnmarshalText(data) },
	func(data []byte) (hostsIterator, error) { e := new(HostsFileEntry); return e, e.UnmarshalText(data) },
	func(data []byte) (hostsIterator, error) { e := new(WildcardEntry); return e, e.UnmarshalText(data) },
}

func (h *HostsIterator) UnmarshalText(data []byte) error {
	var mErr *multierror.Error

	for _, parse := range hostsEntryParsers {
		entry, err := parse(data)
		if err != nil {
			mErr = multierror.Append(mErr, err)

			continue
		}

		h.hostsIterator = entry

		return nil
	}

	flatErr := multierror.Flatten(mErr)
	if flatErr != nil {
		return fmt.Errorf("failed to parse hosts entry: %w", flatErr)
	}

	return nil
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
	fields := bytes.Fields(data)
	if len(fields) == 0 {
		return errors.New("empty entry")
	}

	host, err := normalizeHostsListEntry(string(fields[0]))
	if err != nil {
		return err
	}

	if len(fields) > 1 {
		return fmt.Errorf("unexpected second column: %s", fields[1])
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
	fields := bytes.Fields(data)
	if len(fields) == 0 {
		return errors.New("empty entry")
	}

	ipStr := string(fields[0])

	var netInterface string

	// Remove interface part
	if idx := strings.IndexRune(ipStr, '%'); idx != -1 {
		// if `netInterface` is empty it's technically an invalid entry, but we'll ignore that here
		netInterface = ipStr[idx+1:]
		ipStr = ipStr[:idx]
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid ip: %s", fields[0])
	}

	hosts := make([]string, 0, len(fields)-1) // there must be at least one host for the line to be valid

	for _, field := range fields[1:] {
		host := string(field)

		if err := validateDomainName(host); err != nil {
			return err
		}

		hosts = append(hosts, host)
	}

	if len(hosts) == 0 {
		return errors.New("expected at least one host following IP")
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

// WildcardEntry is single domain wildcard.
type WildcardEntry string

func (e WildcardEntry) String() string {
	return string(e)
}

// We assume this is used with `Lines`:
// - data will never be empty
// - comments are stripped
func (e *WildcardEntry) UnmarshalText(data []byte) error {
	fields := bytes.Fields(data)
	if len(fields) == 0 {
		return errors.New("empty entry")
	}

	entry := string(fields[0])

	if !strings.HasPrefix(entry, "*.") || strings.Count(entry, "*") > 1 {
		return fmt.Errorf("unsupported wildcard '%s': must start with '*.' and contain no other '*'", entry)
	}

	*e = WildcardEntry(entry)

	return nil
}

func (e WildcardEntry) forEachHost(callback func(string) error) error {
	return callback(e.String())
}

func normalizeHostsListEntry(host string) (string, error) {
	var err error
	var hostUnicode string
	// Lookup is the profile preferred for DNS queries, we use Punycode here as it does less validation.
	// That avoids rejecting domains in a list for reasons that amount to "that domain should not be used"
	// since the goal of the list is to determine whether the domain should be used or not, we leave
	// that decision to it.
	idnaProfile := idna.Punycode

	// remove optional start and end markers for ABP styled lists
	host = strings.TrimPrefix(host, "||")
	host = strings.TrimSuffix(host, "^")

	if !isRegex(host) {
		hostUnicode, err = idnaProfile.ToUnicode(host)
		if err != nil || hostUnicode == host {
			host, err = idnaProfile.ToASCII(host)
			if err != nil {
				return "", fmt.Errorf("%w: %s", err, host)
			}
		}
	}

	if err := validateHostsListEntry(host); err != nil {
		return "", err
	}

	return host, nil
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

func isRegex(host string) bool {
	return strings.HasPrefix(host, "/") && strings.HasSuffix(host, "/")
}

func validateHostsListEntry(host string) error {
	if net.ParseIP(host) != nil {
		return nil
	}

	if isRegex(host) {
		if _, err := regexp.Compile(host); err != nil {
			return fmt.Errorf("invalid regex in hosts entry '%s': %w", host, err)
		}

		return nil
	}

	return validateDomainName(host)
}
