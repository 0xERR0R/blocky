package lists

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/evt"
	"github.com/avast/retry-go/v4"
)

// cacheDirPermission is used when creating the on-disk download cache directory.
const cacheDirPermission os.FileMode = 0o750

// TransientError represents a temporary error like timeout, network errors...
type TransientError struct {
	inner error
}

func (e *TransientError) Error() string {
	return fmt.Sprintf("temporary error occurred: %v", e.inner)
}

func (e *TransientError) Unwrap() error {
	return e.inner
}

// httpStatusError represents a download that reached the server but received a
// non-success HTTP status. It is distinct from connection/timeout/DNS errors so
// callers can tell "the host answered with an error" apart from "the host was
// unreachable" (only the latter justifies falling back to a stale cached copy).
type httpStatusError struct {
	code int
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("got status code %d", e.code)
}

// FileDownloader is able to download some text file
type FileDownloader interface {
	DownloadFile(ctx context.Context, link string) (io.ReadCloser, error)
}

// httpDownloader downloads files via HTTP protocol
type httpDownloader struct {
	cfg config.Downloader

	client http.Client
}

func NewDownloader(cfg config.Downloader, transport http.RoundTripper) FileDownloader {
	inner := newDownloader(cfg, transport)

	if cfg.CachePath == "" {
		return inner
	}

	if err := os.MkdirAll(cfg.CachePath, cacheDirPermission); err != nil {
		logger().WithError(err).Warnf(
			"cannot create download cache dir %s, continuing without on-disk cache", cfg.CachePath)

		return inner
	}

	return newCachingDownloader(inner, cfg.CachePath)
}

func newDownloader(cfg config.Downloader, transport http.RoundTripper) *httpDownloader {
	return &httpDownloader{
		cfg: cfg,

		client: http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout.ToDuration(),
		},
	}
}

// downloadResponse is the result of a single (retried) HTTP download attempt.
type downloadResponse struct {
	statusCode int
	header     http.Header
	body       io.ReadCloser // nil iff statusCode == http.StatusNotModified
}

func (d *httpDownloader) DownloadFile(ctx context.Context, link string) (io.ReadCloser, error) {
	resp, err := d.download(ctx, link, nil)
	if err != nil {
		return nil, err
	}

	if resp.body == nil {
		// DownloadFile never sends conditional headers, so a 304 (nil body) should be
		// impossible here; guard defensively rather than returning a nil reader.
		return nil, fmt.Errorf("unexpected 304 Not Modified for unconditional request to '%s'", link)
	}

	return resp.body, nil
}

// download performs a GET (with the given optional request headers) and retries on
// transient errors. 200 and 304 are both treated as success; any other status retries.
func (d *httpDownloader) download(ctx context.Context, link string, reqHeader http.Header) (*downloadResponse, error) {
	var result *downloadResponse

	err := retry.Do(
		func() error {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
			if err != nil {
				return fmt.Errorf("failed to create HTTP request for '%s': %w", link, err)
			}

			for name, values := range reqHeader {
				for _, value := range values {
					req.Header.Add(name, value)
				}
			}

			resp, httpErr := d.client.Do(req)
			if httpErr == nil {
				if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotModified {
					result = &downloadResponse{statusCode: resp.StatusCode, header: resp.Header, body: resp.Body}

					if resp.StatusCode == http.StatusNotModified {
						// Drain body before closing to allow connection reuse
						_, _ = io.Copy(io.Discard, resp.Body)
						_ = resp.Body.Close()
						result.body = nil
					}

					return nil
				}

				// Drain body before closing to allow connection reuse
				// See: https://pkg.go.dev/net/http#Response.Body
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()

				return &httpStatusError{code: resp.StatusCode}
			}

			var netErr net.Error
			if errors.As(httpErr, &netErr) && netErr.Timeout() {
				return &TransientError{inner: netErr}
			}

			return fmt.Errorf("HTTP request to '%s' failed: %w", link, httpErr)
		},
		retry.Attempts(d.cfg.Attempts),
		retry.DelayType(retry.FixedDelay),
		retry.Delay(d.cfg.Cooldown.ToDuration()),
		retry.LastErrorOnly(true),
		retry.OnRetry(d.logRetry(link)))
	if err != nil {
		return nil, fmt.Errorf("failed to download file from '%s': %w", link, err)
	}

	return result, nil
}

// logRetry returns a retry.OnRetry callback that logs the cause of each failed
// download attempt and emits the failed-download event.
func (d *httpDownloader) logRetry(link string) func(n uint, err error) {
	return func(n uint, err error) {
		var transientErr *TransientError

		var dnsErr *net.DNSError

		logger := logger().
			WithField("link", link).
			WithField("attempt", fmt.Sprintf("%d/%d", n+1, d.cfg.Attempts))

		switch {
		case errors.As(err, &transientErr):
			logger.Warnf("Temporary network err / Timeout occurred: %s", transientErr)
		case errors.As(err, &dnsErr):
			logger.Warnf("Name resolution err: %s", dnsErr.Err)
		default:
			logger.Warnf("Can't download file: %s", err)
		}

		onDownloadError(link)
	}
}

func onDownloadError(link string) {
	evt.Bus().Publish(evt.CachingFailedDownloadChanged, link)
}
