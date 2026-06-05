package lists

import (
	"errors"
	"io"
	"os"
	"path/filepath"

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
