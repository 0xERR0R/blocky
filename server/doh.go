package server

import (
	"encoding/base64"
	"io"
	"net/http"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/service"
	"github.com/0xERR0R/blocky/util"
	"github.com/go-chi/chi/v5"
	"github.com/miekg/dns"
)

type dohService struct {
	service.SimpleHTTP

	handler dnsHandler
}

func newDoHService(cfg config.DoHService, handler dnsHandler) *dohService {
	endpoints := util.ConcatSlices(
		service.EndpointsFromAddrs(service.HTTPProtocol, cfg.Addrs.HTTP),
		service.EndpointsFromAddrs(service.HTTPSProtocol, cfg.Addrs.HTTPS),
	)

	s := &dohService{
		SimpleHTTP: service.NewSimpleHTTP("DoH", endpoints),

		handler: handler,
	}

	s.Mux.Route("/dns-query", func(mux chi.Router) {
		// Handlers for / also handle /dns-query without trailing slash

		mux.Get("/", s.handleGET)
		mux.Get("/{clientID}", s.handleGET)

		mux.Post("/", s.handlePOST)
		mux.Post("/{clientID}", s.handlePOST)
	})

	return s
}

func (s *dohService) handleGET(rw http.ResponseWriter, req *http.Request) {
	dnsParam, ok := req.URL.Query()["dns"]
	if !ok || len(dnsParam[0]) < 1 {
		http.Error(rw, "dns param is missing", http.StatusBadRequest)

		return
	}

	rawMsg, err := base64.RawURLEncoding.DecodeString(dnsParam[0])
	if err != nil {
		http.Error(rw, "wrong message format", http.StatusBadRequest)

		return
	}

	if len(rawMsg) > dohMessageLimit {
		http.Error(rw, "URI Too Long", http.StatusRequestURITooLong)

		return
	}

	s.processDohMessage(rawMsg, rw, req)
}

func (s *dohService) handlePOST(rw http.ResponseWriter, req *http.Request) {
	contentType := req.Header.Get("Content-type")
	if contentType != dnsContentType {
		http.Error(rw, "unsupported content type", http.StatusUnsupportedMediaType)

		return
	}

	rawMsg, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)

		return
	}

	if len(rawMsg) > dohMessageLimit {
		http.Error(rw, "Payload Too Large", http.StatusRequestEntityTooLarge)

		return
	}

	s.processDohMessage(rawMsg, rw, req)
}

func (s *dohService) processDohMessage(rawMsg []byte, rw http.ResponseWriter, httpReq *http.Request) {
	msg := new(dns.Msg)
	if err := msg.Unpack(rawMsg); err != nil {
		logger().Error("can't deserialize message: ", err)
		http.Error(rw, err.Error(), http.StatusBadRequest)

		return
	}

	ctx, dnsReq := newRequestFromHTTP(httpReq.Context(), httpReq, msg)

	s.handler(ctx, dnsReq, httpMsgWriter{rw})
}

type httpMsgWriter struct {
	rw http.ResponseWriter
}

func (r httpMsgWriter) WriteMsg(msg *dns.Msg) error {
	b, err := msg.Pack()
	if err != nil {
		return err
	}

	r.rw.Header().Set("content-type", dnsContentType)

	// https://www.rfc-editor.org/rfc/rfc8484#section-4.2.1
	r.rw.WriteHeader(http.StatusOK)

	_, err = r.rw.Write(b)

	return err
}
