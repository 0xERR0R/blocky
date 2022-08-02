package helpertest

import (
	"bufio"
	"os"
	"path/filepath"
)

type TempFolder struct {
	Path   string
	Error  error
	prefix string
}

func NewTempFolder(prefix string) *TempFolder {
	ipref := prefix

	if len(ipref) == 0 {
		ipref = "blocky"
	}

	path, err := os.MkdirTemp("", ipref)

	res := &TempFolder{
		Path:   path,
		Error:  err,
		prefix: ipref,
	}

	return res
}

func (tf *TempFolder) Clean() error {
	if len(tf.Path) > 0 {
		return os.RemoveAll(tf.Path)
	}

	return nil
}

func (tf *TempFolder) CreateSubFolder(name string) *TempFolder {
	var path string

	var err error

	if len(name) > 0 {
		path = filepath.Join(tf.Path, name)
		err = os.Mkdir(path, 0750)
	} else {
		path, err = os.MkdirTemp(tf.Path, tf.prefix)
	}

	res := &TempFolder{
		Path:   path,
		Error:  err,
		prefix: tf.prefix,
	}

	return res
}

func (tf *TempFolder) CreateEmptyFile(name string) (string, error) {
	f, err := tf.createFile(name)

	if err != nil {
		return "", err
	}

	return checkState(f, err)
}

func (tf *TempFolder) CreateStringFile(name string, lines ...string) (string, error) {
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
	}

	return os.CreateTemp(tf.Path, "temp")
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
