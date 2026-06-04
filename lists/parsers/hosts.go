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
	maxDNSLabelLength   = 63  // https://www.rfc-editor.org/rfc/rfc1034#section-3.1
)

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
	// Lookup is the profile preferred for DNS queries, we use Punycode here as it does less validation.
	// That avoids rejecting domains in a list for reasons that amount to "that domain should not be used"
	// since the goal of the list is to determine whether the domain should be used or not, we leave
	// that decision to it.
	idnaProfile := idna.Punycode

	// remove optional start and end markers for ABP styled lists
	host = strings.TrimPrefix(host, "||")
	host = strings.TrimSuffix(host, "^")

	// IDNA is only needed for entries that contain non-ASCII (Unicode) characters,
	// or an "xn--" ACE prefix (which IDNA validates even when the input is already
	// ASCII). For all other (pure-ASCII) entries the ToUnicode/ToASCII dance leaves
	// the host unchanged, so skip it — IDNA is comparatively expensive and the vast
	// majority of list entries are plain ASCII.
	if !isRegex(host) && needsIDNA(host) {
		hostUnicode, err := idnaProfile.ToUnicode(host)
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

// needsIDNA reports whether host requires IDNA processing: any non-ASCII byte
// needs it, and so does an "xn--" ACE prefix (matched case-insensitively and
// conservatively anywhere in the string), since IDNA validates punycode labels
// even for ASCII input. Pure-ASCII input without an ACE prefix is left unchanged
// by IDNA, so it can safely skip it.
func needsIDNA(host string) bool {
	for i := 0; i < len(host); i++ {
		c := host[i]
		if c >= 0x80 {
			return true
		}

		if (c == 'x' || c == 'X') && i+3 < len(host) &&
			(host[i+1] == 'n' || host[i+1] == 'N') &&
			host[i+2] == '-' && host[i+3] == '-' {
			return true
		}
	}

	return false
}

func validateDomainName(host string) error {
	if len(host) > maxDomainNameLength {
		return fmt.Errorf("domain name is too long: %s", host)
	}

	if isValidDomainName(host) {
		return nil
	}

	return fmt.Errorf("invalid domain name: %s", host)
}

// isValidDomainName reports whether host matches the (relaxed) domain grammar
// `^[a-zA-Z0-9_-]{1,63}(\.[a-zA-Z0-9_-]{1,63})*[\._]?$`: dot-separated labels of
// 1..63 label characters, with an optional single trailing '.' or '_'.
//
// Labels have no restriction on their start or end (e.g. leading/trailing
// hyphens are allowed) to avoid rejecting list entries for reasons that amount
// to "that domain should not be used"; deciding that is the list's job.
//
// This replaces a regexp; the two trailing-character possibilities (” or the
// final '.'/'_') mirror the regex's optional `[\._]?` group exactly.
func isValidDomainName(host string) bool {
	if isLabelSequence(host) {
		return true
	}

	// The grammar allows one optional trailing '.' or '_' after the last label.
	if n := len(host); n > 0 {
		if last := host[n-1]; last == '.' || last == '_' {
			return isLabelSequence(host[:n-1])
		}
	}

	return false
}

// isLabelSequence reports whether s is `LABEL("."LABEL)*` with each LABEL being
// 1..63 domain-label characters.
func isLabelSequence(s string) bool {
	labelLen := 0

	for i := 0; i < len(s); i++ {
		c := s[i]

		if c == '.' {
			if labelLen == 0 {
				return false // empty label (leading dot or "..")
			}

			labelLen = 0

			continue
		}

		if !isDNSLabelChar(c) {
			return false
		}

		labelLen++
		if labelLen > maxDNSLabelLength {
			return false
		}
	}

	return labelLen != 0 // reject empty input and a trailing '.'
}

func isDNSLabelChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z',
		c >= 'A' && c <= 'Z',
		c >= '0' && c <= '9',
		c == '-', c == '_':
		return true
	default:
		return false
	}
}

func isRegex(host string) bool {
	return strings.HasPrefix(host, "/") && strings.HasSuffix(host, "/")
}

// MightBeIP reports whether s could possibly be parsed as an IP by net.ParseIP,
// i.e. it is non-empty and contains only characters that appear in IPv4/IPv6
// literals. It is a cheap pre-check used to avoid calling net.ParseIP (which
// allocates) on the overwhelming majority of entries, which are domain names.
// It never returns false for a string that net.ParseIP would accept.
func MightBeIP(s string) bool {
	if s == "" {
		return false
	}

	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9',
			c >= 'a' && c <= 'f',
			c >= 'A' && c <= 'F',
			c == '.', c == ':':
		default:
			return false
		}
	}

	return true
}

func validateHostsListEntry(host string) error {
	if MightBeIP(host) && net.ParseIP(host) != nil {
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
