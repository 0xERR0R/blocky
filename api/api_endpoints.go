package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/util"

	"github.com/go-chi/chi/v5"
)

const (
	contentTypeHeader = "content-type"
	jsonContentType   = "application/json"
)

// BlockingControl interface to control the blocking status
type BlockingControl interface {
	EnableBlocking()
	DisableBlocking(duration time.Duration, disableGroups []string) error
	BlockingStatus() BlockingStatus
}

// ClientDNSResolverControl interface to control the blocking status
type ClientDNSResolverControl interface {
	EnableClientDNSResolver()
	DisableClientDNSResolver(duration time.Duration, disableGroups []string) error
	ClientDNSResolverStatus() BlockingStatus
}

// ListRefresher interface to control the list refresh
type ListRefresher interface {
	RefreshLists()
}

// BlockingEndpoint endpoint for the blocking status control
type BlockingEndpoint struct {
	control BlockingControl
}

// BlockingEndpoint endpoint for the blocking status control
type ClientDNSResolverEndpoint struct {
	control ClientDNSResolverControl
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

	if a, ok := t.(ClientDNSResolverControl); ok {
		registerClientDNSResolverEndpoints(router, a)
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
func (l *ListRefreshEndpoint) apiListRefresh(rw http.ResponseWriter, _ *http.Request) {
	rw.Header().Set(contentTypeHeader, jsonContentType)
	l.refresher.RefreshLists()
}

func registerBlockingEndpoints(router chi.Router, control BlockingControl) {
	s := &BlockingEndpoint{control}
	// register API endpoints
	router.Get(PathBlockingEnablePath, s.apiBlockingEnable)
	router.Get(PathBlockingDisablePath, s.apiBlockingDisable)
	router.Get(PathBlockingStatusPath, s.apiBlockingStatus)
}

func registerClientDNSResolverEndpoints(router chi.Router, control ClientDNSResolverControl) {
	s := &ClientDNSResolverEndpoint{control}
	// register API endpoints
	router.Get(PathClientDNSResolverEnablePath, s.apiClientDNSResolverEnable)
	router.Get(PathClientDNSResolverDisablePath, s.apiClientDNSResolverDisable)
	router.Get(PathClientDNSResolverStatusPath, s.apiClientDNSResolverStatus)
}

// apiBlockingEnable is the http endpoint to enable the blocking status
// @Summary Enable blocking
// @Description enable the blocking status
// @Tags blocking
// @Success 200   "Blocking is enabled"
// @Router /blocking/enable [get]
func (s *BlockingEndpoint) apiBlockingEnable(rw http.ResponseWriter, _ *http.Request) {
	log.Log().Info("enabling blocking...")

	s.control.EnableBlocking()
	rw.Header().Set(contentTypeHeader, jsonContentType)
	_, err := rw.Write([]byte("{}"))

	if err != nil {
		log.Log().Error("Can't send an empty answer: ", log.EscapeInput(err.Error()))
	}
}

// apiClientDNSResolverEnable is the http endpoint to enable the client dns resolver status
// @Summary Enable client dns resolver
// @Description enable the client dns resolver status
// @Tags blocking
// @Success 200   "Blocking is enabled"
// @Router /blocking/enable [get]
func (s *ClientDNSResolverEndpoint) apiClientDNSResolverEnable(rw http.ResponseWriter, _ *http.Request) {
	log.Log().Info("enabling blocking...")

	s.control.EnableClientDNSResolver()

	rw.Header().Set(contentTypeHeader, jsonContentType)
	_, err := rw.Write([]byte("{}"))

	if err != nil {
		log.Log().Error("Can't send an empty answer: ", log.EscapeInput(err.Error()))
	}
}

// apiDisableClientDNSResolver is the http endpoint to disable the blocking status
// @Summary Disable client dns resolver
// @Description disable the client dns resolver for client
// @Tags blocking
// @Param duration query string false "duration of blocking (Example: 300s, 5m, 1h, 5m30s)" Format(duration)
// @Param groups query string false "groups to disable (comma separated). If empty, disable all groups" Format(string)
// @Success 200   "Blocking is disabled"
// @Failure 400   "Wrong duration format"
// @Failure 400   "Unknown group"
// @Router /blocking/disable [get]
func (s *ClientDNSResolverEndpoint) apiClientDNSResolverDisable(rw http.ResponseWriter, req *http.Request) {
	var (
		duration time.Duration
		groups   []string
		err      error
	)

	rw.Header().Set(contentTypeHeader, jsonContentType)

	// parse duration from query parameter
	durationParam := req.URL.Query().Get("duration")
	if len(durationParam) > 0 {
		duration, err = time.ParseDuration(durationParam)
		if err != nil {
			log.Log().Errorf("wrong duration format '%s'", log.EscapeInput(durationParam))
			rw.WriteHeader(http.StatusBadRequest)

			return
		}
	}

	groupsParam := req.URL.Query().Get("groups")
	if len(groupsParam) > 0 {
		groups = strings.Split(groupsParam, ",")
	}

	err = s.control.DisableClientDNSResolver(duration, groups)
	if err != nil {
		log.Log().Error("can't dns disable the blocking: ", log.EscapeInput(err.Error()))
		rw.WriteHeader(http.StatusBadRequest)
	} else {
		log.Log().Warn("Blocking request acknowledged but not sent to redis: ")
		rw.WriteHeader(http.StatusOK)
		_, err := rw.Write([]byte("{}"))

		if err != nil {
			log.Log().Error("Can't send an empty answer: ", log.EscapeInput(err.Error()))
		}
	}
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

	rw.Header().Set(contentTypeHeader, jsonContentType)

	// parse duration from query parameter
	durationParam := req.URL.Query().Get("duration")
	if len(durationParam) > 0 {
		duration, err = time.ParseDuration(durationParam)
		if err != nil {
			log.Log().Errorf("wrong duration format '%s'", log.EscapeInput(durationParam))
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
		log.Log().Error("can't disable the blocking: ", log.EscapeInput(err.Error()))
		rw.WriteHeader(http.StatusBadRequest)
	} else {
		rw.WriteHeader(http.StatusOK)
		_, err := rw.Write([]byte("{}"))

		if err != nil {
			log.Log().Error("Can't send an empty answer: ", log.EscapeInput(err.Error()))
		}
	}
}

// apiClientDNSResolverStatus is the http endpoint to get current client dns resolver status
// @Summary client dns resolver status
// @Description get current client dns resolver status
// @Tags client dns resolver
// @Produce  json
// @Success 200 {object} api.BlockingStatus "Returns current blocking status"
// @Router /blocking/status [get]
func (s *ClientDNSResolverEndpoint) apiClientDNSResolverStatus(rw http.ResponseWriter, _ *http.Request) {
	status := s.control.ClientDNSResolverStatus()

	rw.Header().Set(contentTypeHeader, jsonContentType)

	response, err := json.Marshal(status)
	util.LogOnError("unable to marshal response ", err)

	_, err = rw.Write(response)
	util.LogOnError("unable to write response ", err)
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

	rw.Header().Set(contentTypeHeader, jsonContentType)

	response, err := json.Marshal(status)
	util.LogOnError("unable to marshal response ", err)

	_, err = rw.Write(response)
	util.LogOnError("unable to write response ", err)
}
