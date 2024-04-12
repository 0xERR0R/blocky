package lists

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

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
				return err
			}

			resp, httpErr := d.client.Do(req)
			if httpErr == nil {
				if resp.StatusCode == http.StatusOK {
					body = resp.Body

					return nil
				}

				_ = resp.Body.Close()

				return fmt.Errorf("got status code %d", resp.StatusCode)
			}

			var netErr net.Error
			if errors.As(httpErr, &netErr) && netErr.Timeout() {
				return &TransientError{inner: netErr}
			}

			return httpErr
		},
		retry.Attempts(d.cfg.Attempts),
		retry.DelayType(retry.FixedDelay),
		retry.Delay(d.cfg.Cooldown.ToDuration()),
		retry.LastErrorOnly(true),
		retry.OnRetry(func(n uint, err error) {
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
		}))

	return body, err
}

func onDownloadError(link string) {
	evt.Bus().Publish(evt.CachingFailedDownloadChanged, link)
}
