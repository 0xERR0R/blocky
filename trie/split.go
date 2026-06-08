package trie

import "strings"

type SplitFunc func(string) (label, rest string)

// www.example.com -> ("com", "www.example")
func SplitTLD(domain string) (label, rest string) {
	domain = strings.TrimRight(domain, ".")

	idx := strings.LastIndexByte(domain, '.')
	if idx == -1 {
		return domain, ""
	}

	label = domain[idx+1:]
	rest = domain[:idx]

	return label, rest
}

// JoinTLD is the inverse of SplitTLD: it reconstructs an entry from the labels
// returned by HasParentOf on a trie built with SplitTLD.
// ["example", "com"] -> "example.com"
func JoinTLD(labels []string) string {
	return strings.Join(labels, ".")
}
