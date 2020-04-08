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
)

type BlockingStatus struct {
	// True if blocking is enabled
	Enabled bool `json:"enabled"`
	// If blocking is temporary disabled: amount of seconds until blocking will be enabled
	AutoEnableInSec uint `json:"autoEnableInSec"`
}
