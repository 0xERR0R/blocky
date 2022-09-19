package helpertest

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
)

type TmpFolder struct {
	Path   string
	Error  error
	prefix string
}

type TmpFile struct {
	Path   string
	Error  error
	Folder *TmpFolder
}

func NewTmpFolder(prefix string) *TmpFolder {
	ipref := prefix

	if len(ipref) == 0 {
		ipref = "blocky"
	}

	path, err := os.MkdirTemp("", ipref)

	res := &TmpFolder{
		Path:   path,
		Error:  err,
		prefix: ipref,
	}

	return res
}

func (tf *TmpFolder) Clean() error {
	if len(tf.Path) > 0 {
		return os.RemoveAll(tf.Path)
	}

	return nil
}

func (tf *TmpFolder) CreateSubFolder(name string) *TmpFolder {
	var path string

	var err error

	if len(name) > 0 {
		path = filepath.Join(tf.Path, name)
		err = os.Mkdir(path, fs.ModePerm)
	} else {
		path, err = os.MkdirTemp(tf.Path, tf.prefix)
	}

	res := &TmpFolder{
		Path:   path,
		Error:  err,
		prefix: tf.prefix,
	}

	return res
}

func (tf *TmpFolder) CreateEmptyFile(name string) *TmpFile {
	f, err := tf.createFile(name)

	if err != nil {
		return tf.newErrorTmpFile(err)
	}

	return tf.checkState(f, err)
}

func (tf *TmpFolder) CreateStringFile(name string, lines ...string) *TmpFile {
	f, err := tf.createFile(name)

	if err != nil {
		return tf.newErrorTmpFile(err)
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

	return tf.checkState(f, err)
}

func (tf *TmpFolder) JoinPath(name string) string {
	return filepath.Join(tf.Path, name)
}

func (tf *TmpFolder) CountFiles() (int, error) {
	files, err := os.ReadDir(tf.Path)
	if err != nil {
		return 0, err
	}

	return len(files), nil
}

func (tf *TmpFolder) createFile(name string) (*os.File, error) {
	if len(name) > 0 {
		return os.Create(filepath.Join(tf.Path, name))
	}

	return os.CreateTemp(tf.Path, "temp")
}

func (tf *TmpFolder) newErrorTmpFile(err error) *TmpFile {
	return &TmpFile{
		Path:   "",
		Error:  err,
		Folder: tf,
	}
}

func (tf *TmpFolder) checkState(file *os.File, ierr error) *TmpFile {
	err := ierr
	filepath := ""

	if file != nil {
		filepath = file.Name()

		file.Close()

		_, err = os.Stat(filepath)
	}

	return &TmpFile{
		Path:   filepath,
		Error:  err,
		Folder: tf,
	}
}

func (tf *TmpFile) Stat() error {
	if tf.Error != nil {
		return tf.Error
	}

	_, res := os.Stat(tf.Path)

	return res
}
