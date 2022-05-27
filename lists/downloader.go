package lists

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/0xERR0R/blocky/evt"
	"github.com/avast/retry-go/v4"
)

const (
	defaultDownloadTimeout  = time.Second
	defaultDownloadAttempts = uint(1)
	defaultDownloadCooldown = 500 * time.Millisecond
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
	DownloadFile(link string) (io.ReadCloser, error)
}

// HTTPDownloader downloads files via HTTP protocol
type HTTPDownloader struct {
	downloadTimeout  time.Duration
	downloadAttempts uint
	downloadCooldown time.Duration
	httpTransport    *http.Transport
}

type DownloaderOption func(c *HTTPDownloader)

func NewDownloader(options ...DownloaderOption) *HTTPDownloader {
	d := &HTTPDownloader{
		downloadTimeout:  defaultDownloadTimeout,
		downloadAttempts: defaultDownloadAttempts,
		downloadCooldown: defaultDownloadCooldown,
		httpTransport:    &http.Transport{},
	}

	for _, opt := range options {
		opt(d)
	}

	return d
}

// WithTimeout sets the download timeout
func WithTimeout(timeout time.Duration) DownloaderOption {
	return func(d *HTTPDownloader) {
		d.downloadTimeout = timeout
	}
}

// WithTimeout sets the pause between 2 download attempts
func WithCooldown(cooldown time.Duration) DownloaderOption {
	return func(d *HTTPDownloader) {
		d.downloadCooldown = cooldown
	}
}

// WithTimeout sets the attempt number for retry
func WithAttempts(downloadAttempts uint) DownloaderOption {
	return func(d *HTTPDownloader) {
		d.downloadAttempts = downloadAttempts
	}
}

// WithTimeout sets the HTTP transport
func WithTransport(httpTransport *http.Transport) DownloaderOption {
	return func(d *HTTPDownloader) {
		d.httpTransport = httpTransport
	}
}

func (d *HTTPDownloader) DownloadFile(link string) (io.ReadCloser, error) {
	client := http.Client{
		Timeout:   d.downloadTimeout,
		Transport: d.httpTransport,
	}

	logger().WithField("link", link).Info("starting download")

	var body io.ReadCloser

	err := retry.Do(
		func() error {
			var resp *http.Response
			var httpErr error
			if resp, httpErr = client.Get(link); httpErr == nil {
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
		retry.Attempts(d.downloadAttempts),
		retry.DelayType(retry.FixedDelay),
		retry.Delay(d.downloadCooldown),
		retry.LastErrorOnly(true),
		retry.OnRetry(func(n uint, err error) {
			var transientErr *TransientError

			var dnsErr *net.DNSError

			logger := logger().WithField("link", link).WithField("attempt",
				fmt.Sprintf("%d/%d", n+1, d.downloadAttempts))

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
