package lists

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
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

// cacheValidators holds the HTTP validators last seen for a source URL.
type cacheValidators struct {
	etag         string
	lastModified string
}

// cachingDownloader decorates an httpDownloader with an on-disk body cache and
// HTTP conditional requests. Validators are kept in memory only (lost on restart).
type cachingDownloader struct {
	inner *httpDownloader
	dir   string

	mu         sync.Mutex
	validators map[string]cacheValidators
}

func newCachingDownloader(inner *httpDownloader, dir string) *cachingDownloader {
	return &cachingDownloader{
		inner:      inner,
		dir:        dir,
		validators: make(map[string]cacheValidators),
	}
}

func (c *cachingDownloader) setValidators(link, etag, lastModified string) {
	if etag == "" && lastModified == "" {
		return
	}

	c.mu.Lock()
	c.validators[link] = cacheValidators{etag: etag, lastModified: lastModified}
	c.mu.Unlock()
}

func (c *cachingDownloader) conditionalHeader(link string) http.Header {
	c.mu.Lock()
	v, ok := c.validators[link]
	c.mu.Unlock()

	if !ok {
		return nil
	}

	h := make(http.Header, 2)
	if v.etag != "" {
		h.Set("If-None-Match", v.etag)
	}

	if v.lastModified != "" {
		h.Set("If-Modified-Since", v.lastModified)
	}

	if len(h) == 0 {
		return nil
	}

	return h
}

func (c *cachingDownloader) DownloadFile(ctx context.Context, link string) (io.ReadCloser, error) {
	resp, err := c.inner.download(ctx, link, c.conditionalHeader(link))
	if err != nil {
		if cached, openErr := openCached(c.dir, link); openErr == nil {
			logger().WithField("link", link).Warn("download failed, using cached copy")

			return cached, nil
		}

		return nil, err
	}

	if resp.statusCode == http.StatusNotModified {
		cached, openErr := openCached(c.dir, link)
		if openErr == nil {
			logger().WithField("link", link).Debug("source not modified, using cached copy")

			return cached, nil
		}

		// Validators say unchanged but the cache file is gone: force a full download.
		resp, err = c.inner.download(ctx, link, nil)
		if err != nil {
			return nil, err
		}

		if resp.body == nil {
			// A forced unconditional GET sends no validators, so a 304 (nil body) is impossible.
			return nil, fmt.Errorf("unexpected 304 Not Modified on forced unconditional request for '%s'", link)
		}
	}

	return c.serveAndStore(link, resp)
}

// serveAndStore returns a reader over the 200 body that tees into a temp file and,
// once fully read, atomically renames it to the cache file and stores the validators.
func (c *cachingDownloader) serveAndStore(link string, resp *downloadResponse) (io.ReadCloser, error) {
	tmp, err := os.CreateTemp(c.dir, "dl-*.tmp")
	if err != nil {
		logger().WithError(err).Warnf("cannot create temp cache file in %s, serving without caching", c.dir)

		return resp.body, nil
	}

	finalPath := cacheFilePath(c.dir, link)
	etag := resp.header.Get("ETag")
	lastModified := resp.header.Get("Last-Modified")

	tw := &tolerantFileWriter{w: tmp}

	fin := &cacheFinalizer{
		body: resp.body,
		tmp:  tmp,
	}
	fin.tee = io.TeeReader(resp.body, tw)
	fin.finalize = func() {
		if tw.failed {
			// a mid-stream write error already abandoned the cache copy
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())

			return
		}

		if err := tmp.Sync(); err != nil {
			logger().WithError(err).Warn("cache fsync failed, discarding temp file")
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())

			return
		}

		_ = tmp.Close()

		if err := os.Rename(tmp.Name(), finalPath); err != nil {
			logger().WithError(err).Warnf("cannot finalize cache file %s", finalPath)
			_ = os.Remove(tmp.Name())

			return
		}

		c.setValidators(link, etag, lastModified)
	}

	return fin, nil
}

// tolerantFileWriter writes to an underlying writer but never propagates a write
// error to its caller. Used with io.TeeReader so that a mid-stream disk write
// failure (e.g. the disk fills up during a download) does NOT surface as a read
// error to the list parser: the download/parse still succeeds over the network and
// only the on-disk cache copy is abandoned. The first failure is logged and sets
// failed; subsequent writes are silently skipped.
type tolerantFileWriter struct {
	w      io.Writer
	failed bool
}

func (w *tolerantFileWriter) Write(p []byte) (int, error) {
	if w.failed {
		return len(p), nil
	}

	if _, err := w.w.Write(p); err != nil {
		w.failed = true

		logger().WithError(err).Warn("cache write failed, abandoning on-disk copy")
	}

	return len(p), nil
}

// cacheFinalizer tees the network body into a temp file and finalizes (rename +
// store validators) exactly once when the reader is fully consumed to EOF.
// If the consumer stops early, Close discards the temp file and keeps any previous copy.
// It is not safe for concurrent use; it follows the single-consumer io.ReadCloser contract.
type cacheFinalizer struct {
	body     io.ReadCloser
	tee      io.Reader
	tmp      *os.File
	finalize func()
	done     bool
}

func (f *cacheFinalizer) Read(p []byte) (int, error) {
	n, err := f.tee.Read(p)
	if err == io.EOF && !f.done {
		f.done = true
		f.finalize()
	}

	return n, err
}

func (f *cacheFinalizer) Close() error {
	err := f.body.Close()

	if !f.done {
		_ = f.tmp.Close()
		_ = os.Remove(f.tmp.Name())
	}

	return err
}

// Ensure cachingDownloader satisfies the FileDownloader interface.
var _ FileDownloader = (*cachingDownloader)(nil)
