package trie

import (
	"github.com/0xERR0R/blocky/log"
	"strings"
)

// Trie stores a set of strings and can quickly check
// if it contains an element, or one of its parents.
//
// It implements a semi-radix/semi-compressed trie:
// a node that would be a single child is merged with
// its parent, if it is a terminal.
//
// The word "prefix" is avoided because in practice
// we use the `Trie` with `SplitTLD` so parents are
// suffixes even if in the datastructure they are
// prefixes.
type Trie struct {
	split SplitFunc
	root  parent
}

func NewTrie(split SplitFunc) *Trie {
	return &Trie{
		split: split,
		root:  parent{},
	}
}

func (t *Trie) IsEmpty() bool {
	return t.root.children == nil
}

func (t *Trie) Insert(key string) {
	t.root.insert(key, t.split)
}

func (t *Trie) HasParentOf(key string) bool {
	return t.root.hasParentOf(key, t.split)
}

type node interface {
	hasParentOf(key string, split SplitFunc) bool
}

// We save memory by not keeping track of children of
// nodes that are terminals (part of the set) as we only
// ever need to know if a domain, or any of its parents,
// is in the `Trie`.
// Example: if the `Trie` contains "example.com", inserting
// "www.example.com" has no effect as we already know it
// is contained in the set.
// Conversely, if it contains "www.example.com" and we insert
// "example.com", then "www.example.com" is removed as it is
// no longer useful.
//
// This means that all terminals are leafs and vice-versa.
// So we save slightly more memory by avoiding a `isTerminal bool`
// per parent.
type parent struct {
	children map[string]node
}

func newParent() *parent {
	return &parent{
		children: make(map[string]node, 1),
	}
}

func (n *parent) insert(key string, split SplitFunc) {
	if len(key) == 0 {
		return
	}

	for {
		if n.children == nil {
			n.children = make(map[string]node, 1)
		}

		label, rest := split(key)

		child, ok := n.children[label]
		if !ok || len(rest) == 0 {
			n.children[label] = terminal(rest)

			return
		}

		switch child := child.(type) {
		case *parent:
			// Continue down the trie
			key = rest
			n = child

			continue

		case terminal:
			if child.hasParentOf(rest, split) {
				// Found a parent/"prefix" in the set
				return
			}

			p := newParent()
			n.children[label] = p

			p.insert(child.String(), split) // keep existing terminal
			p.insert(rest, split)           // add new value

			return
		}
	}
}

func (n *parent) hasParentOf(key string, split SplitFunc) bool {
	searchString := key
	rule := ""

	for {
		label, rest := split(key)
		rule = strings.Join([]string{label, rule}, ".")

		child, ok := n.children[label]
		if !ok {
			return false
		}

		switch child := child.(type) {
		case *parent:
			if len(rest) == 0 {
				// The trie only contains children/"suffixes" of the
				// key we're searching for
				return false
			}

			// Continue down the trie
			key = rest
			n = child

			continue

		case terminal:
			// Continue down the trie
			matched := child.hasParentOf(rest, split)
			if matched {
				rule = strings.Join([]string{child.String(), rule}, ".")
				rule = strings.Trim(rule, ".")
				log.PrefixedLog("trie").Debugf("wildcard block rule '%s' matched with '%s'", rule, searchString)
			}

			return matched
		}
	}
}

type terminal string

func (t terminal) String() string {
	return string(t)
}

func (t terminal) hasParentOf(searchKey string, split SplitFunc) bool {
	tKey := t.String()
	if tKey == "" {
		return true
	}

	for {
		tLabel, tRest := split(tKey)

		searchLabel, searchRest := split(searchKey)
		if searchLabel != tLabel {
			return false
		}

		if len(tRest) == 0 {
			// Found a parent/"prefix" in the set
			return true
		}

		if len(searchRest) == 0 {
			// The trie only contains children/"suffixes" of the
			// key we're searching for
			return false
		}

		// Continue down the trie
		searchKey = searchRest
		tKey = tRest
	}
}
