package lists

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/evt"
	"github.com/avast/retry-go/v4"
)

const (
	// retryJitter is the maximum jitter to add to retry delays to prevent thundering herd
	retryJitter = 500 * time.Millisecond

	// idleConnTimeout is how long idle connections are kept in the pool
	idleConnTimeout = 90 * time.Second
)

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
	return newDownloader(cfg, transport)
}

func newDownloader(cfg config.Downloader, transport http.RoundTripper) *httpDownloader {
	// Apply fine-grained timeouts to transport if it's an *http.Transport
	if t, ok := transport.(*http.Transport); ok {
		// Note: DialTimeout is set via DialContext, not as a field on Transport
		t.TLSHandshakeTimeout = cfg.TLSHandshakeTimeout.ToDuration()
		t.ResponseHeaderTimeout = cfg.ResponseHeaderTimeout.ToDuration()
	}

	return &httpDownloader{
		cfg: cfg,

		client: http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout.ToDuration(),
		},
	}
}

func (d *httpDownloader) DownloadFile(ctx context.Context, link string) (io.ReadCloser, error) {
	var body io.ReadCloser

	err := retry.Do(
		func() error {
			return d.attemptDownload(ctx, link, &body)
		},
		retry.Attempts(d.cfg.Attempts),
		retry.DelayType(retry.BackOffDelay),
		retry.Delay(d.cfg.Cooldown.ToDuration()),
		retry.MaxDelay(d.cfg.MaxBackoff.ToDuration()),
		retry.MaxJitter(retryJitter),
		retry.LastErrorOnly(true),
		retry.OnRetry(func(n uint, err error) {
			d.logRetryAttempt(link, n, err)
			onDownloadError(link)
		}))
	if err != nil {
		return nil, fmt.Errorf("failed to download file from '%s': %w", link, err)
	}

	return body, nil
}

func (d *httpDownloader) attemptDownload(ctx context.Context, link string, body *io.ReadCloser) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request for '%s': %w", link, err)
	}

	resp, httpErr := d.client.Do(req)
	if httpErr != nil {
		return d.handleNetworkError(link, httpErr)
	}

	return d.handleHTTPResponse(link, resp, body)
}

func (d *httpDownloader) handleHTTPResponse(link string, resp *http.Response, body *io.ReadCloser) error {
	switch resp.StatusCode {
	case http.StatusOK:
		*body = resp.Body

		return nil

	case http.StatusNotFound, http.StatusGone:
		// Permanent errors - don't retry
		drainAndClose(resp.Body)
		// Emit event for permanent errors since OnRetry won't be called
		onDownloadError(link)

		return retry.Unrecoverable(fmt.Errorf("permanent error: status code %d", resp.StatusCode))

	case http.StatusTooManyRequests, http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusGatewayTimeout:
		// Transient errors that need backoff
		drainAndClose(resp.Body)

		return &TransientError{inner: fmt.Errorf("transient error: status code %d", resp.StatusCode)}

	default:
		// Other HTTP errors - retry with normal backoff
		drainAndClose(resp.Body)

		return fmt.Errorf("HTTP error: status code %d", resp.StatusCode)
	}
}

func (d *httpDownloader) handleNetworkError(link string, httpErr error) error {
	// Network-level errors
	var netErr net.Error
	if errors.As(httpErr, &netErr) && netErr.Timeout() {
		return &TransientError{inner: netErr}
	}

	var dnsErr *net.DNSError
	if errors.As(httpErr, &dnsErr) {
		// DNS errors are often transient
		return &TransientError{inner: dnsErr}
	}

	return fmt.Errorf("HTTP request to '%s' failed: %w", link, httpErr)
}

func (d *httpDownloader) logRetryAttempt(link string, attemptNum uint, err error) {
	logger := logger().
		WithField("link", link).
		WithField("attempt", fmt.Sprintf("%d/%d", attemptNum+1, d.cfg.Attempts))

	switch {
	case isDNSError(err):
		logger.Warnf("Name resolution err: %s", extractDNSError(err).Err)
	case isTransientError(err):
		logger.Warnf("Temporary network err / Timeout occurred: %s", err)
	default:
		logger.Warnf("Can't download file: %s", err)
	}
}

func isDNSError(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}

	var transientErr *TransientError
	if errors.As(err, &transientErr) {
		return errors.As(transientErr.inner, &dnsErr)
	}

	return false
}

func isTransientError(err error) bool {
	var transientErr *TransientError

	return errors.As(err, &transientErr)
}

func extractDNSError(err error) *net.DNSError {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr
	}

	var transientErr *TransientError
	if errors.As(err, &transientErr) {
		if errors.As(transientErr.inner, &dnsErr) {
			return dnsErr
		}
	}

	return nil
}

// drainAndClose drains the response body and closes it to allow connection reuse
// See: https://pkg.go.dev/net/http#Response.Body
func drainAndClose(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, body)
	_ = body.Close()
}

func onDownloadError(link string) {
	evt.Bus().Publish(evt.CachingFailedDownloadChanged, link)
}
