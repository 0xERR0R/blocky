package lists

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/0xERR0R/blocky/log"
)

// cacheFilePath returns the on-disk path for a source URL: <dir>/<sha256hex(url)>.
func cacheFilePath(dir, url string) string {
	sum := sha256.Sum256([]byte(url))

	return filepath.Join(dir, hex.EncodeToString(sum[:]))
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

	// setValidators only stores an entry when at least one validator is non-empty,
	// so a present entry always yields at least one conditional header.
	h := make(http.Header, 2)
	if v.etag != "" {
		h.Set("If-None-Match", v.etag)
	}

	if v.lastModified != "" {
		h.Set("If-Modified-Since", v.lastModified)
	}

	return h
}

func (c *cachingDownloader) DownloadFile(ctx context.Context, link string) (io.ReadCloser, error) {
	resp, err := c.inner.download(ctx, link, c.conditionalHeader(link))
	if err != nil {
		// Only serve the stale cached copy when the source was unreachable
		// (connection/timeout/DNS error). If the host answered with an HTTP error
		// status (4xx/5xx) it is reachable, so we surface the error and let the
		// existing in-memory cache stand rather than masking a removed/changed source.
		var statusErr *httpStatusError
		if !errors.As(err, &statusErr) {
			if cached, openErr := openCached(c.dir, link); openErr == nil {
				logger().WarnContext(ctx, "download failed, using cached copy", slog.String("link", link), log.AttrError(err))

				return cached, nil
			}
		}

		return nil, err
	}

	if resp.statusCode == http.StatusNotModified {
		cached, openErr := openCached(c.dir, link)
		if openErr == nil {
			logger().DebugContext(ctx, "source not modified, using cached copy", slog.String("link", link))

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
		logger().Warn(fmt.Sprintf("cannot create temp cache file in %s, serving without caching", c.dir), log.AttrError(err))

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

		// No fsync: the cache is regenerable disposable state. A torn write after a
		// crash is tolerated by the parser and corrected by the next refresh, so the
		// durability cost of fsync-per-download is not worth it.
		_ = tmp.Close()

		if err := os.Rename(tmp.Name(), finalPath); err != nil {
			logger().Warn("cannot finalize cache file "+finalPath, log.AttrError(err))
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

		logger().Warn("cache write failed, abandoning on-disk copy", log.AttrError(err))
	}

	return len(p), nil
}

// cacheFinalizer tees the network body into a temp file and finalizes (rename +
// store validators) exactly once when the whole body has been teed to disk.
// If the consumer stops before EOF (e.g. the parser aborts after too many errors),
// Close drains the rest of the body into the temp file so the cache still captures
// the full download and the HTTP connection can be reused; a read error during the
// drain (e.g. context cancellation or a mid-stream network failure) leaves the temp
// file discarded and any previous cached copy untouched.
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
	if errors.Is(err, io.EOF) && !f.done {
		f.done = true
		f.finalize()
	}

	return n, err
}

func (f *cacheFinalizer) Close() error {
	if !f.done {
		// Drain whatever the consumer left unread through the tee so the cache file
		// holds the complete body. io.Copy treats io.EOF as success; any other error
		// (cancelled context, mid-stream reset) leaves done=false and the temp file is
		// discarded below.
		if _, err := io.Copy(io.Discard, f.tee); err == nil {
			f.done = true
			f.finalize()
		}
	}

	err := f.body.Close()

	if !f.done {
		_ = f.tmp.Close()
		_ = os.Remove(f.tmp.Name())
	}

	return err
}

// Ensure cachingDownloader satisfies the FileDownloader interface.
var _ FileDownloader = (*cachingDownloader)(nil)
