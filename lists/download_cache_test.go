package lists

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/config"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Download cache helpers", func() {
	Describe("cacheFilePath", func() {
		It("is deterministic and hex-encoded per URL", func() {
			p1 := cacheFilePath("/cache", "http://example.com/list.txt")
			p2 := cacheFilePath("/cache", "http://example.com/list.txt")
			p3 := cacheFilePath("/cache", "http://example.com/other.txt")

			Expect(p1).Should(Equal(p2))
			Expect(p1).ShouldNot(Equal(p3))
			Expect(filepath.Dir(p1)).Should(Equal("/cache"))
			Expect(filepath.Base(p1)).Should(HaveLen(64)) // sha256 hex
		})
	})

	Describe("PruneCache", func() {
		It("removes files not referenced by the kept URLs and leaves the rest", func() {
			dir := GinkgoT().TempDir()
			keepURL := "http://example.com/keep.txt"
			keepName := filepath.Base(cacheFilePath(dir, keepURL))

			Expect(os.WriteFile(filepath.Join(dir, keepName), []byte("x"), 0o600)).Should(Succeed())
			Expect(os.WriteFile(filepath.Join(dir, "deadbeef-orphan"), []byte("x"), 0o600)).Should(Succeed())
			Expect(os.WriteFile(filepath.Join(dir, "dl-123.tmp"), []byte("x"), 0o600)).Should(Succeed())

			Expect(PruneCache(dir, []string{keepURL})).Should(Succeed())

			entries, err := os.ReadDir(dir)
			Expect(err).Should(Succeed())
			Expect(entries).Should(HaveLen(1))
			Expect(entries[0].Name()).Should(Equal(keepName))
		})

		It("is a no-op when the directory does not exist", func() {
			Expect(PruneCache(filepath.Join(GinkgoT().TempDir(), "missing"), nil)).Should(Succeed())
		})
	})

	Describe("openCached", func() {
		It("returns a reader with the cached content (hit)", func() {
			dir := GinkgoT().TempDir()
			url := "http://example.com/list.txt"
			content := []byte("cached body")

			Expect(os.WriteFile(cacheFilePath(dir, url), content, 0o600)).Should(Succeed())

			rc, err := openCached(dir, url)
			Expect(err).Should(Succeed())

			defer rc.Close()

			got, err := io.ReadAll(rc)
			Expect(err).Should(Succeed())
			Expect(got).Should(Equal(content))
		})

		It("returns an os.ErrNotExist error when the cache file is absent (miss)", func() {
			dir := GinkgoT().TempDir()

			_, err := openCached(dir, "http://absent")
			Expect(err).Should(HaveOccurred())
			Expect(errors.Is(err, os.ErrNotExist)).Should(BeTrue())
		})
	})
})

var _ = Describe("cachingDownloader", func() {
	var (
		dir   string
		sut   *cachingDownloader
		dlCfg config.Downloader
	)

	BeforeEach(func() {
		var err error
		dlCfg, err = config.WithDefaults[config.Downloader]()
		Expect(err).Should(Succeed())
		dlCfg.Attempts = 1
		dlCfg.Cooldown = config.Duration(time.Millisecond)

		dir = GinkgoT().TempDir()
		sut = newCachingDownloader(newDownloader(dlCfg, nil), dir)
	})

	readAll := func(r io.ReadCloser) string {
		defer r.Close()
		buf := new(strings.Builder)
		_, err := io.Copy(buf, r)
		Expect(err).Should(Succeed())

		return buf.String()
	}

	When("a 200 response is downloaded", func() {
		It("returns the body and writes it to disk", func(ctx context.Context) {
			server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				_, _ = rw.Write([]byte("a.com\nb.com"))
			}))
			DeferCleanup(server.Close)

			reader, err := sut.DownloadFile(ctx, server.URL)
			Expect(err).Should(Succeed())
			Expect(readAll(reader)).Should(Equal("a.com\nb.com")) // draining to EOF finalizes the cache file

			onDisk, err := os.ReadFile(cacheFilePath(dir, server.URL))
			Expect(err).Should(Succeed())
			Expect(string(onDisk)).Should(Equal("a.com\nb.com"))

			entries, err := os.ReadDir(dir)
			Expect(err).Should(Succeed())
			Expect(entries).Should(HaveLen(1)) // no leftover temp file
		})
	})

	When("the reader is closed before EOF", func() {
		It("does not finalize a cache file and leaves no temp file", func(ctx context.Context) {
			server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				_, _ = rw.Write([]byte("a.com\nb.com\nc.com"))
			}))
			DeferCleanup(server.Close)

			reader, err := sut.DownloadFile(ctx, server.URL)
			Expect(err).Should(Succeed())

			buf := make([]byte, 3)
			_, _ = reader.Read(buf) // read a little, but not to EOF
			Expect(reader.Close()).Should(Succeed())

			_, statErr := os.Stat(cacheFilePath(dir, server.URL))
			Expect(os.IsNotExist(statErr)).Should(BeTrue())

			entries, err := os.ReadDir(dir)
			Expect(err).Should(Succeed())
			Expect(entries).Should(BeEmpty())
		})
	})
})
