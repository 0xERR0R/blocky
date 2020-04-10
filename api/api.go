// @title blocky API
// @description blocky API

// @contact.name blocky@github
// @contact.url https://github.com/0xERR0R/blocky

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @BasePath /api/
package api

const (
	BlockingStatusPath  = "/api/blocking/status"
	BlockingEnablePath  = "/api/blocking/enable"
	BlockingDisablePath = "/api/blocking/disable"
	BlockingQueryPath   = "/api/query"
)

type QueryRequest struct {
	// query for DNS request
	Query string
	// request type (A, AAAA, ...)
	Type string
}

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

type BlockingStatus struct {
	// True if blocking is enabled
	Enabled bool `json:"enabled"`
	// If blocking is temporary disabled: amount of seconds until blocking will be enabled
	AutoEnableInSec uint `json:"autoEnableInSec"`
}
