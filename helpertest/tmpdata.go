package helpertest

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type TmpFolder struct {
	Path   string
	prefix string
}

type TmpFile struct {
	Path   string
	Folder *TmpFolder
}

func NewTmpFolder(prefix string) *TmpFolder {
	ipref := prefix

	if len(ipref) == 0 {
		ipref = "blocky"
	}

	path, err := os.MkdirTemp("", ipref)
	Expect(err).Should(Succeed())

	res := &TmpFolder{
		Path:   path,
		prefix: ipref,
	}

	DeferCleanup(res.Clean)

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

	Expect(err).Should(Succeed())

	res := &TmpFolder{
		Path:   path,
		prefix: tf.prefix,
	}

	return res
}

func (tf *TmpFolder) CreateEmptyFile(name string) *TmpFile {
	f, res := tf.createFile(name)
	defer f.Close()

	return res
}

func (tf *TmpFolder) CreateStringFile(name string, lines ...string) *TmpFile {
	f, res := tf.createFile(name)
	defer f.Close()

	first := true
	w := bufio.NewWriter(f)

	for _, l := range lines {
		if first {
			first = false
		} else {
			_, err := w.WriteString("\n")
			Expect(err).Should(Succeed())
		}

		_, err := w.WriteString(l)
		Expect(err).Should(Succeed())
	}

	w.Flush()

	return res
}

func (tf *TmpFolder) JoinPath(name string) string {
	return filepath.Join(tf.Path, name)
}

func (tf *TmpFolder) createFile(name string) (*os.File, *TmpFile) {
	var (
		f   *os.File
		err error
	)

	if len(name) > 0 {
		f, err = os.Create(filepath.Join(tf.Path, name))
	} else {
		f, err = os.CreateTemp(tf.Path, "temp")
	}

	Expect(err).Should(Succeed())

	return f, &TmpFile{
		Path:   f.Name(),
		Folder: tf,
	}
}
