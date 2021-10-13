// @title blocky API
// @description blocky API

// @contact.name blocky@github
// @contact.url https://github.com/0xERR0R/blocky

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @BasePath /api/

// Package api provides basic API structs for the REST services
package api

const (
	// PathBlockingStatusPath defines the REST endpoint for blocking status
	PathBlockingStatusPath = "/api/blocking/status"

	// PathBlockingEnablePath defines the REST endpoint for blocking enable
	PathBlockingEnablePath = "/api/blocking/enable"

	// PathBlockingDisablePath defines the REST endpoint for blocking disable
	PathBlockingDisablePath = "/api/blocking/disable"

	// PathListsRefresh defines the REST endpoint for blocking refresh
	PathListsRefresh = "/api/lists/refresh"

	// PathQueryPath defines the REST endpoint for query
	PathQueryPath = "/api/query"

	// PathDohQuery DoH Url
	PathDohQuery = "/dns-query"
)

// QueryRequest is a data structure for a DNS request
type QueryRequest struct {
	// query for DNS request
	Query string
	// request type (A, AAAA, ...)
	Type string
}

// QueryResult is a data structure for the DNS result
type QueryResult struct {
	// blocky reason for resolution
	Reason string `json:"reason"`
	// response type (CACHED, BLOCKED, ...)
	ResponseType string `json:"responseType"`
	// actual DNS response
	Response string `json:"response"`
	// DNS return code (NOERROR, NXDOMAIN, ...)
	ReturnCode string `json:"returnCode"`
}

// BlockingStatus represents the current blocking status
type BlockingStatus struct {
	// True if blocking is enabled
	Enabled bool `json:"enabled"`
	// Disabled group names
	DisabledGroups []string `json:"disabledGroups"`
	// If blocking is temporary disabled: amount of seconds until blocking will be enabled
	AutoEnableInSec uint `json:"autoEnableInSec"`
}
