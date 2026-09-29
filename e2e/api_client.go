package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/0xERR0R/blocky/auth"
)

const (
	// csrfHeader is the header auth.RequireCSRFHeader demands on every
	// mutating request. Its value is irrelevant; only its presence matters.
	csrfHeader = "X-Requested-With"

	apiClientTimeout = 5 * time.Second
	apiLoginAttempts = 3
	apiLoginBackoff  = 500 * time.Millisecond
)

// apiClient is an authenticated HTTP client for one blocky container's /api/*
// surface.
//
// Every /api/* path sits behind auth.RequireAuth whenever a config store is
// present (server/server_endpoints.go), and the fork always has a store, so an
// unauthenticated spec gets 401 rather than an answer. The client logs in for
// real — POST /api/auth/login against the account seedAPIUser put in the
// store — instead of forging a session row, so the cookie the specs carry is
// the one a browser would get and the session path is exercised rather than
// bypassed.
//
// Get and Post mirror http.Get / http.Post so they drop into the existing
// Eventually(http.Get).WithArguments(url) call sites unchanged.
type apiClient struct {
	http    *http.Client
	session *http.Cookie
}

// newAPIClient logs in against the given base URL ("http://host:port") and
// returns a client carrying the resulting session cookie.
func newAPIClient(ctx context.Context, baseURL string) (*apiClient, error) {
	client := &http.Client{Timeout: apiClientTimeout}

	var lastErr error

	for attempt := range apiLoginAttempts {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(apiLoginBackoff):
			}
		}

		cookie, err := login(ctx, client, baseURL)
		if err == nil {
			return &apiClient{http: client, session: cookie}, nil
		}

		lastErr = err
	}

	return nil, fmt.Errorf("log in to %s: %w", baseURL, lastErr)
}

func login(ctx context.Context, client *http.Client, baseURL string) (*http.Cookie, error) {
	body, err := json.Marshal(map[string]string{
		"username": e2eAPIUsername,
		"password": e2eAPIPassword,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/api/auth/login", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(csrfHeader, "e2e")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)

		return nil, fmt.Errorf("login returned %d: %s", resp.StatusCode, msg)
	}

	for _, c := range resp.Cookies() {
		if c.Name == auth.SessionCookieName || c.Name == auth.SessionCookieNameSecure {
			return c, nil
		}
	}

	return nil, fmt.Errorf("login returned no %q cookie", auth.SessionCookieName)
}

// Get performs an authenticated GET. Signature matches http.Get so it can be
// handed to Eventually(...).WithArguments(url).
func (c *apiClient) Get(url string) (*http.Response, error) {
	return c.do(http.MethodGet, url, "", nil)
}

// Post performs an authenticated POST. Signature matches http.Post.
func (c *apiClient) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	return c.do(http.MethodPost, url, contentType, body)
}

func (c *apiClient) do(method, url, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body) //nolint:noctx // matches the http.Get/http.Post shape the specs use
	if err != nil {
		return nil, err
	}

	req.AddCookie(c.session)
	req.Header.Set(csrfHeader, "e2e")

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	return c.http.Do(req)
}
