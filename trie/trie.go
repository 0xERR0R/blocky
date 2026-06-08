package trie

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

// HasParentOf reports whether the trie contains key or one of its parents.
// On a match it also returns the labels of the matched entry; joining them
// with the separator used by the trie's SplitFunc reproduces the entry.
// The labels are nil when there is no match.
func (t *Trie) HasParentOf(key string) ([]string, bool) {
	// labels are built only on the matching path (during recursion unwind),
	// so a miss does not allocate. They come back in entry order, ready to be
	// joined by the caller with the separator matching its SplitFunc.
	return t.root.hasParentOf(key, t.split)
}

type node interface {
	hasParentOf(key string, split SplitFunc) (labels []string, ok bool)
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
			if _, ok := child.hasParentOf(rest, split); ok {
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

func (n *parent) hasParentOf(key string, split SplitFunc) ([]string, bool) {
	label, rest := split(key)

	child, ok := n.children[label]
	if !ok {
		return nil, false
	}

	// A *parent child means the trie only stores longer entries/"suffixes" below
	// this node; if the search key has no more labels, none of them can be a
	// parent of it.
	if _, isParent := child.(*parent); isParent && len(rest) == 0 {
		return nil, false
	}

	labels, ok := child.hasParentOf(rest, split)
	if !ok {
		return nil, false
	}

	// On the matching path only: prepend-by-append this node's label. The deeper
	// labels were collected first, so appending the current (more significant)
	// label keeps the entry's natural order.
	return append(labels, label), true
}

type terminal string

func (t terminal) String() string {
	return string(t)
}

func (t terminal) hasParentOf(searchKey string, split SplitFunc) ([]string, bool) {
	tKey := t.String()
	if tKey == "" {
		return nil, true
	}

	// labels of this terminal, collected only while it keeps matching so a
	// mismatch stays allocation-free.
	var labels []string

	for {
		tLabel, tRest := split(tKey)

		searchLabel, searchRest := split(searchKey)
		if searchLabel != tLabel {
			return nil, false
		}

		labels = append(labels, tLabel)

		if len(tRest) == 0 {
			// Found a parent/"prefix" in the set. labels are in peel order
			// (most significant last); reverse them into entry order so the
			// caller's parent nodes can append their labels after these.
			for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
				labels[i], labels[j] = labels[j], labels[i]
			}

			return labels, true
		}

		if len(searchRest) == 0 {
			// The trie only contains children/"suffixes" of the
			// key we're searching for
			return nil, false
		}

		// Continue down the trie
		searchKey = searchRest
		tKey = tRest
	}
}
