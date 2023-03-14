package stringcache

type GroupedStringCache interface {
	Contains(searchString string, groups []string) []string
	Refresh(group string) GroupFactory
	ElementCount(group string) int
}

type GroupFactory interface {
	AddEntry(entry string)
	Count() int
	Finish()
}
