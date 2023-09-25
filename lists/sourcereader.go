package lists

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/0xERR0R/blocky/config"
)

type SourceOpener interface {
	fmt.Stringer

	Open() (io.ReadCloser, error)
}

func NewSourceOpener(txtLocInfo string, source config.BytesSource, downloader FileDownloader) (SourceOpener, error) {
	switch source.Type {
	case config.BytesSourceTypeText:
		return &textOpener{source: source, locInfo: txtLocInfo}, nil

	case config.BytesSourceTypeHttp:
		return &httpOpener{source: source, downloader: downloader}, nil

	case config.BytesSourceTypeFile:
		return &fileOpener{source: source}, nil
	}

	return nil, fmt.Errorf("cannot open %s", source)
}

type textOpener struct {
	source  config.BytesSource
	locInfo string
}

func (o *textOpener) Open() (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(o.source.From)), nil
}

func (o *textOpener) String() string {
	return fmt.Sprintf("%s: %s", o.locInfo, o.source)
}

type httpOpener struct {
	source     config.BytesSource
	downloader FileDownloader
}

func (o *httpOpener) Open() (io.ReadCloser, error) {
	return o.downloader.DownloadFile(o.source.From)
}

func (o *httpOpener) String() string {
	return o.source.String()
}

type fileOpener struct {
	source config.BytesSource
}

func (o *fileOpener) Open() (io.ReadCloser, error) {
	return os.Open(o.source.From)
}

func (o *fileOpener) String() string {
	return o.source.String()
}
