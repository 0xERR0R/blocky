package lists

import (
	"blocky/helpertest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_NoMatch_With_Empty_List(t *testing.T) {
	file1 := helpertest.TempFile("#empty file\n\n")
	defer os.Remove(file1.Name())

	lists := map[string][]string{
		"gr1": {file1.Name()},
	}

	sut := NewListCache(lists)

	found, group := sut.Match("google.com", []string{"gr1"})
	assert.Equal(t, false, found)
	assert.Equal(t, "", group)
}

func Test_Match_Download_Multiple_Groups(t *testing.T) {
	server1 := helpertest.TestServer("blocked1.com\nblocked1a.com")
	defer server1.Close()

	server2 := helpertest.TestServer("blocked2.com")
	defer server2.Close()

	server3 := helpertest.TestServer("blocked3.com\nblocked1a.com")
	defer server3.Close()

	lists := map[string][]string{
		"gr1": {server1.URL, server2.URL},
		"gr2": {server3.URL},
	}

	sut := NewListCache(lists)

	found, group := sut.Match("blocked1.com", []string{"gr1", "gr2"})
	assert.Equal(t, true, found)
	assert.Equal(t, "gr1", group)

	found, group = sut.Match("blocked1a.com", []string{"gr1", "gr2"})
	assert.Equal(t, true, found)
	assert.Equal(t, "gr1", group)

	found, group = sut.Match("blocked1a.com", []string{"gr2"})
	assert.Equal(t, true, found)
	assert.Equal(t, "gr2", group)
}

func Test_Match_Download_No_Group(t *testing.T) {
	server1 := helpertest.TestServer("blocked1.com\nblocked1a.com")
	defer server1.Close()

	server2 := helpertest.TestServer("blocked2.com")
	defer server2.Close()

	server3 := helpertest.TestServer("blocked3.com\nblocked1a.com")
	defer server3.Close()

	lists := map[string][]string{
		"gr1":          {server1.URL, server2.URL},
		"gr2":          {server3.URL},
		"withDeadLink": {"http://wrong.host.name"},
	}

	sut := NewListCache(lists)

	found, group := sut.Match("blocked1.com", []string{})
	assert.Equal(t, false, found)
	assert.Equal(t, "", group)
}

func Test_Match_Files_Multiple_Groups(t *testing.T) {
	file1 := helpertest.TempFile("blocked1.com\nblocked1a.com")
	defer os.Remove(file1.Name())

	file2 := helpertest.TempFile("blocked2.com")
	defer os.Remove(file2.Name())

	file3 := helpertest.TempFile("blocked3.com\nblocked1a.com")
	defer os.Remove(file3.Name())

	lists := map[string][]string{
		"gr1": {file1.Name(), file2.Name()},
		"gr2": {"file://" + file3.Name()},
	}

	sut := NewListCache(lists)

	found, group := sut.Match("blocked1.com", []string{"gr1", "gr2"})
	assert.Equal(t, true, found)
	assert.Equal(t, "gr1", group)

	found, group = sut.Match("blocked1a.com", []string{"gr1", "gr2"})
	assert.Equal(t, true, found)
	assert.Equal(t, "gr1", group)

	found, group = sut.Match("blocked1a.com", []string{"gr2"})
	assert.Equal(t, true, found)
	assert.Equal(t, "gr2", group)
}

func Test_Configuration(t *testing.T) {
	lists := map[string][]string{
		"gr1": {"file1", "file2"},
	}

	sut := NewListCache(lists)

	c := sut.Configuration()

	assert.Len(t, c, 7)
}
