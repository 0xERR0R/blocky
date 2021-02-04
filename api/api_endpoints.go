package api

import (
	"blocky/util"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	log "github.com/sirupsen/logrus"
)

type BlockingControl interface {
	EnableBlocking()
	DisableBlocking(duration time.Duration)
	BlockingStatus() BlockingStatus
}

type BlockingEndpoint struct {
	control BlockingControl
}

func RegisterEndpoint(router chi.Router, t interface{}) {
	if bc, ok := t.(BlockingControl); ok {
		registerBlockingEndpoints(router, bc)
	}
}

func registerBlockingEndpoints(router chi.Router, control BlockingControl) {
	s := &BlockingEndpoint{control}
	// register API endpoints
	router.Get(BlockingEnablePath, s.apiBlockingEnable)
	router.Get(BlockingDisablePath, s.apiBlockingDisable)
	router.Get(BlockingStatusPath, s.apiBlockingStatus)
}

// apiBlockingEnable is the http endpoint to enable the blocking status
// @Summary Enable blocking
// @Description enable the blocking status
// @Tags blocking
// @Success 200   "Blocking is enabled"
// @Router /blocking/enable [get]
func (s *BlockingEndpoint) apiBlockingEnable(_ http.ResponseWriter, _ *http.Request) {
	log.Info("enabling blocking...")

	s.control.EnableBlocking()
}

// apiBlockingDisable is the http endpoint to disable the blocking status
// @Summary Disable blocking
// @Description disable the blocking status
// @Tags blocking
// @Param duration query string false "duration of blocking (Example: 300s, 5m, 1h, 5m30s)" Format(duration)
// @Success 200   "Blocking is disabled"
// @Failure 400   "Wrong duration format"
// @Router /blocking/disable [get]
func (s *BlockingEndpoint) apiBlockingDisable(rw http.ResponseWriter, req *http.Request) {
	var (
		duration time.Duration
		err      error
	)

	// parse duration from query parameter
	durationParam := req.URL.Query().Get("duration")
	if len(durationParam) > 0 {
		duration, err = time.ParseDuration(durationParam)
		if err != nil {
			log.Errorf("wrong duration format '%s'", durationParam)
			rw.WriteHeader(http.StatusBadRequest)

			return
		}
	}

	s.control.DisableBlocking(duration)
}

// apiBlockingStatus is the http endpoint to get current blocking status
// @Summary Blocking status
// @Description get current blocking status
// @Tags blocking
// @Produce  json
// @Success 200 {object} api.BlockingStatus "Returns current blocking status"
// @Router /blocking/status [get]
func (s *BlockingEndpoint) apiBlockingStatus(rw http.ResponseWriter, _ *http.Request) {
	status := s.control.BlockingStatus()

	response, _ := json.Marshal(status)
	_, err := rw.Write(response)

	util.LogOnError("unable to write response ", err)
}
