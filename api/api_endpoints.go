package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/util"

	"github.com/go-chi/chi"
	log "github.com/sirupsen/logrus"
)

// BlockingControl interface to control the blocking status
type BlockingControl interface {
	EnableBlocking()
	DisableBlocking(duration time.Duration, disableGroups []string) error
	BlockingStatus() BlockingStatus
}

// ListRefresher interface to control the list refresh
type ListRefresher interface {
	RefreshLists()
}

// BlockingEndpoint endpoint for the blocking status control
type BlockingEndpoint struct {
	control BlockingControl
}

// ListRefreshEndpoint endpoint for list refresh
type ListRefreshEndpoint struct {
	refresher ListRefresher
}

// RegisterEndpoint registers an implementation as HTTP endpoint
func RegisterEndpoint(router chi.Router, t interface{}) {
	if a, ok := t.(BlockingControl); ok {
		registerBlockingEndpoints(router, a)
	}

	if a, ok := t.(ListRefresher); ok {
		registerListRefreshEndpoints(router, a)
	}
}

func registerListRefreshEndpoints(router chi.Router, refresher ListRefresher) {
	l := &ListRefreshEndpoint{refresher}

	router.Post(PathListsRefresh, l.apiListRefresh)
}

// apiListRefresh is the http endpoint to trigger the refresh of all lists
// @Summary List refresh
// @Description Refresh all lists
// @Tags lists
// @Success 200   "Lists were reloaded"
// @Router /lists/refresh [post]
func (l *ListRefreshEndpoint) apiListRefresh(_ http.ResponseWriter, _ *http.Request) {
	l.refresher.RefreshLists()
}

func registerBlockingEndpoints(router chi.Router, control BlockingControl) {
	s := &BlockingEndpoint{control}
	// register API endpoints
	router.Get(PathBlockingEnablePath, s.apiBlockingEnable)
	router.Get(PathBlockingDisablePath, s.apiBlockingDisable)
	router.Get(PathBlockingStatusPath, s.apiBlockingStatus)
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
// @Param groups query string false "groups to disable (comma separated). If empty, disable all groups" Format(string)
// @Success 200   "Blocking is disabled"
// @Failure 400   "Wrong duration format"
// @Failure 400   "Unknown group"
// @Router /blocking/disable [get]
func (s *BlockingEndpoint) apiBlockingDisable(rw http.ResponseWriter, req *http.Request) {
	var (
		duration time.Duration
		groups   []string
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

	groupsParam := req.URL.Query().Get("groups")
	if len(groupsParam) > 0 {
		groups = strings.Split(groupsParam, ",")
	}

	err = s.control.DisableBlocking(duration, groups)
	if err != nil {
		log.Error("can't disable the blocking: ", err)
		rw.WriteHeader(http.StatusBadRequest)
	}
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
