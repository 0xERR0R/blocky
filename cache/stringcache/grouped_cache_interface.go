package stringcache

type GroupedStringCache interface {
	// Contains checks if one or more groups in the cache contains the search string.
	// Returns group(s) containing the string or empty slice if string was not found
	Contains(searchString string, groups []string) []string

	// Refresh creates new factory for the group to be refreshed.
	// Calling Finish on the factory will perform the group refresh.
	Refresh(group string) GroupFactory

	// ElementCount returns the amount of elements in the group
	ElementCount(group string) int
}

type GroupFactory interface {
	// AddEntry adds a new string to the factory to be added later to the cache groups.
	AddEntry(entry string)

	// Count returns amount of processed string in the factory
	Count() int

	// Finish replaces the group in cache with factory's content
	Finish()
}
