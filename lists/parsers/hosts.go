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
	"unicode/utf8"

	"github.com/hashicorp/go-multierror"
	"golang.org/x/net/idna"
)

const (
	maxDomainNameLength = 255 // https://www.rfc-editor.org/rfc/rfc1034#section-3.1
	maxDNSLabelLength   = 63  // https://www.rfc-editor.org/rfc/rfc1034#section-3.1
)

// idnaProfile maps an entry to the form DNS clients put on the wire: the UTS #46
// lookup mapping (case folding, NFC, width folding, ignored code points dropped),
// then punycode encoding of non-ASCII labels. Malformed punycode labels fail.
// The STD3 and label validity checks are off: they reject entries for reasons
// that amount to "that domain should not be used", and that decision belongs
// to the list.
//
//nolint:gochecknoglobals
var idnaProfile = idna.New(idna.MapForLookup(), idna.StrictDomainName(false), idna.ValidateLabels(false))

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

func (h *HostsIterator) UnmarshalText(data []byte) error {
	var mErr *multierror.Error

	// Try each entry type in order; the first that parses wins. Candidates are
	// created one at a time so the common case (a host-list entry) only allocates
	// the type that matches, not all three.
	hostList := new(HostListEntry)
	if err := hostList.UnmarshalText(data); err != nil {
		mErr = multierror.Append(mErr, err)
	} else {
		h.hostsIterator = hostList

		return nil
	}

	hostsFile := new(HostsFileEntry)
	if err := hostsFile.UnmarshalText(data); err != nil {
		mErr = multierror.Append(mErr, err)
	} else {
		h.hostsIterator = hostsFile

		return nil
	}

	wildcard := new(WildcardEntry)
	if err := wildcard.UnmarshalText(data); err != nil {
		mErr = multierror.Append(mErr, err)
	} else {
		h.hostsIterator = wildcard

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
		host, err := toASCII(string(field))
		if err != nil {
			return err
		}

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

	entry, err := toASCII(entry)
	if err != nil {
		return err
	}

	// The cache strips the "*." and any surrounding dots, so an empty label here
	// widens the rule: "*..com" would match every .com name.
	if err := validateDomainName(entry[len("*."):]); err != nil {
		return err
	}

	*e = WildcardEntry(entry)

	return nil
}

func (e WildcardEntry) forEachHost(callback func(string) error) error {
	return callback(e.String())
}

func normalizeHostsListEntry(host string) (string, error) {
	// remove optional start and end markers for ABP styled lists
	host = strings.TrimPrefix(host, "||")
	host = strings.TrimSuffix(host, "^")

	// URL-style IPv6 literal, as in "||[2001:db8::1]^"
	if ip, ok := unwrapIPv6Literal(host); ok {
		return ip, nil
	}

	if !isRegex(host) {
		var err error

		host, err = toASCII(host)
		if err != nil {
			return "", err
		}
	}

	if err := validateHostsListEntry(host); err != nil {
		return "", err
	}

	return host, nil
}

// unwrapIPv6Literal strips the brackets of a URL-style IPv6 literal such as
// "[2001:db8::1]". Brackets only wrap IPv6 addresses (RFC 3986), so the domain
// name validation rejects anything else between them.
func unwrapIPv6Literal(s string) (string, bool) {
	if len(s) < 2 || s[0] != '[' || s[len(s)-1] != ']' {
		return "", false
	}

	ip := s[1 : len(s)-1]
	if !strings.Contains(ip, ":") || net.ParseIP(ip) == nil {
		return "", false
	}

	return ip, true
}

// toASCII returns host in the ASCII (A-label) form that DNS queries carry, so
// an entry matches queries however the list spelled it. It keeps ASCII case:
// the caches fold it, and error messages echo the entry as written.
//
// Only entries with non-ASCII (Unicode) characters or an "xn--" ACE prefix
// (which IDNA validates even in ASCII input) need IDNA. Pure-ASCII entries come
// back as is: IDNA is slow next to a byte scan, and most list entries are plain
// ASCII.
func toASCII(host string) (string, error) {
	if !needsIDNA(host) {
		return host, nil
	}

	return idnaToASCII(host)
}

// idnaToASCII maps host with idnaProfile and rejects it when a label vanishes
// in the mapping. An empty "xn--" payload decodes to nothing, and a label made
// only of ignored code points (soft hyphen, zero-width space) maps to nothing;
// either turns "*.com.xn--" into "*.com.", which the cache widens to every
// .com name. The mapping never removes a label separator, so a drop in the
// number of non-empty labels is the sign of a vanished label. A trailing root
// dot in the input stays legitimate.
func idnaToASCII(host string) (string, error) {
	ascii, err := idnaProfile.ToASCII(host)
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, host)
	}

	if nonEmptyLabels(ascii) < nonEmptyLabels(host) {
		return "", fmt.Errorf("label vanishes in IDNA mapping: %s", host)
	}

	return ascii, nil
}

// nonEmptyLabels counts the labels of s that have content. Besides '.', the
// separators are the ideographic and fullwidth full stops that UTS #46 maps to
// '.', so the count of an entry and of its mapping line up.
func nonEmptyLabels(s string) int {
	n, inLabel := 0, false

	for _, r := range s {
		switch r {
		case '.', '\u3002', '\uff0e', '\uff61':
			inLabel = false
		default:
			if !inLabel {
				n++
				inLabel = true
			}
		}
	}

	return n
}

// needsIDNA reports whether host requires IDNA processing: any non-ASCII byte
// needs it, and so does an "xn--" ACE prefix (matched case-insensitively and
// conservatively anywhere in the string), since IDNA validates punycode labels
// even for ASCII input. Pure-ASCII input without an ACE prefix differs from its
// IDNA mapping by ASCII case alone, which the caches fold, so it skips IDNA.
func needsIDNA(host string) bool {
	for i := range len(host) {
		c := host[i]
		if c >= utf8.RuneSelf {
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
// This replaces a regexp; the two trailing-character possibilities ("" or the
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

	for i := range len(s) {
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
	// A regex entry is delimited by slashes (/regex/), so it needs at least an
	// opening and a closing one. Without the length check a lone "/" counts as
	// both prefix and suffix, gets accepted here, and later panics the regex
	// cache when both delimiters are stripped (entry[1:len-1]).
	return len(host) >= 2 && strings.HasPrefix(host, "/") && strings.HasSuffix(host, "/")
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

	for i := range len(s) {
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
