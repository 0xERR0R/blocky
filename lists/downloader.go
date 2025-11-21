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
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
			if err != nil {
				return fmt.Errorf("failed to create HTTP request for '%s': %w", link, err)
			}

			resp, httpErr := d.client.Do(req)
			if httpErr == nil {
				switch resp.StatusCode {
				case http.StatusOK:
					body = resp.Body
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
		},
		retry.Attempts(d.cfg.Attempts),
		retry.DelayType(retry.BackOffDelay),
		retry.Delay(d.cfg.Cooldown.ToDuration()),
		retry.MaxDelay(d.cfg.MaxBackoff.ToDuration()),
		retry.MaxJitter(500*time.Millisecond),
		retry.LastErrorOnly(true),
		retry.OnRetry(func(n uint, err error) {
			var transientErr *TransientError
			var dnsErr *net.DNSError

			logger := logger().
				WithField("link", link).
				WithField("attempt", fmt.Sprintf("%d/%d", n+1, d.cfg.Attempts))

			// Check for DNS errors first (even if wrapped in TransientError)
			if errors.As(err, &dnsErr) {
				logger.Warnf("Name resolution err: %s", dnsErr.Err)
			} else if errors.As(err, &transientErr) {
				// Check if the inner error is a DNS error
				var innerDNSErr *net.DNSError
				if errors.As(transientErr.inner, &innerDNSErr) {
					logger.Warnf("Name resolution err: %s", innerDNSErr.Err)
				} else {
					logger.Warnf("Temporary network err / Timeout occurred: %s", transientErr)
				}
			} else {
				logger.Warnf("Can't download file: %s", err)
			}

			onDownloadError(link)
		}))
	if err != nil {
		return nil, fmt.Errorf("failed to download file from '%s': %w", link, err)
	}

	return body, nil
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
