package trie

// Trie stores a set of strings and can quickly check
// if it contains an element, or one of its parents.
//
// The word "prefix" is avoided because in practice
// we use the `Trie` with `SplitTLD` so parents are
// suffixes even if in the datastructure they are
// prefixes.
type Trie struct {
	split SplitFunc
	root  node
}

func NewTrie(split SplitFunc) *Trie {
	return &Trie{
		split: split,
		root:  node{},
	}
}

func (t *Trie) IsEmpty() bool {
	return t.root.children == nil
}

func (t *Trie) HasParentOf(key string) bool {
	return t.root.hasParentOf(key, t.split)
}

func (t *Trie) Insert(key string) {
	t.root.insert(key, t.split)
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
// per node, and instead use `nil` as the value in the children map.
type node struct {
	children map[string]*node
}

func newParent() *node {
	return &node{
		children: make(map[string]*node, 1),
	}
}

func (n *node) isTerminal() bool {
	// See the comment on `node` for why this holds
	return n == nil
}

func (n *node) hasParentOf(key string, split SplitFunc) bool {
	for {
		label, rest := split(key)

		child, ok := n.children[label]
		if !ok {
			// No related keys are in the trie
			return false
		}

		if child.isTerminal() {
			// Found a parent/"prefix" in the set
			return true
		}

		if len(rest) == 0 {
			// The trie only contains children/"suffixes" of the
			// key we're searching for
			return false
		}

		// Continue down the trie
		key = rest
		n = child
	}
}

func (n *node) insert(key string, split SplitFunc) {
	if len(key) == 0 {
		return
	}

	for {
		if n.children == nil {
			n.children = make(map[string]*node, 1)
		}

		label, rest := split(key)

		if len(rest) == 0 {
			// Don't allocate terminal nodes
			// Also drops any existing children
			n.children[label] = nil

			return
		}

		child, ok := n.children[label]
		if !ok {
			child = newParent()
			n.children[label] = child
		} else if child.isTerminal() {
			// Found a parent/"prefix" in the set
			return
		}

		// Continue down the trie
		key = rest
		n = child
	}
}
