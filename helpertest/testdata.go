package helpertest

import (
	"bufio"
	"os"
	"path/filepath"
)

type TempFolder struct {
	Path  string
	Error error
}

func CreateFolder(prefix string) *TempFolder {
	ipref := prefix

	if len(ipref) == 0 {
		ipref = "blocky"
	}

	path, err := os.MkdirTemp("", ipref)

	res := &TempFolder{
		Path:  path,
		Error: err,
	}

	return res
}

func (tf *TempFolder) Clean() {
	if len(tf.Path) > 0 {
		os.RemoveAll(tf.Path)
	}
}
func (tf *TempFolder) EmptyFile(name string) (string, error) {
	f, err := tf.createFile(name)

	if err != nil {
		return "", err
	}

	return checkState(f, err)
}

func (tf *TempFolder) StringFile(name string, lines ...string) (string, error) {
	f, err := tf.createFile(name)

	if err != nil {
		return "", err
	}

	first := true
	w := bufio.NewWriter(f)
	for _, l := range lines {
		if first {
			first = false
		} else {
			_, err = w.WriteString("\n")
		}

		if err != nil {
			break
		}

		_, err = w.WriteString(l)
		if err != nil {
			break
		}
	}
	w.Flush()

	return checkState(f, err)
}

func (tf *TempFolder) createFile(name string) (*os.File, error) {
	if len(name) > 0 {
		return os.Create(filepath.Join(tf.Path, name))
	} else {
		return os.CreateTemp(tf.Path, "temp")
	}
}

func checkState(file *os.File, ierr error) (string, error) {
	err := ierr
	filepath := ""

	if file != nil {
		filepath = file.Name()

		file.Close()

		_, err = os.Stat(filepath)
	}

	return filepath, err
}
