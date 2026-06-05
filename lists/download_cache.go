package lists

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// cacheFilePath returns the on-disk path for a source URL: <dir>/<sha256hex(url)>.
func cacheFilePath(dir, url string) string {
	sum := sha256.Sum256([]byte(url))

	return filepath.Join(dir, hex.EncodeToString(sum[:]))
}

// PruneCache removes every file in dir that does not correspond to one of keepURLs.
// Stray temp files and bodies of removed sources are deleted. A missing dir is not an error.
// Over-deletion is self-healing: a removed body is simply re-downloaded on the next refresh.
func PruneCache(dir string, keepURLs []string) error {
	if dir == "" {
		return nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}

		return fmt.Errorf("cannot read download cache dir %s: %w", dir, err)
	}

	keep := make(map[string]struct{}, len(keepURLs))
	for _, u := range keepURLs {
		keep[filepath.Base(cacheFilePath(dir, u))] = struct{}{}
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if _, ok := keep[entry.Name()]; ok {
			continue
		}

		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
			logger().WithError(err).Warnf("cannot remove stale cache file %s", entry.Name())
		}
	}

	return nil
}

// openCached returns a reader over the on-disk body for link, or an error if absent.
func openCached(dir, link string) (io.ReadCloser, error) {
	return os.Open(cacheFilePath(dir, link))
}
