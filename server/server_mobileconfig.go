// Copyright 2026 Chris Snell
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"text/template"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/configstore"
	"github.com/0xERR0R/blocky/pkg/advertise"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// mobileconfigNamespace is a deterministic UUID v5 namespace so reinstalling
// a profile replaces rather than duplicates it.
var mobileconfigNamespace = uuid.NewSHA1(uuid.NameSpaceDNS, []byte("blockasaurus.mobileconfig"))

type mobileconfigData struct {
	DisplayName    string
	Identifier     string
	ProfileUUID    string
	PayloadUUID    string
	Slug           string
	DNSProtocol    string // "HTTPS", "TLS", or ""
	ServerURL      string // DoH only
	ServerName     string // DoT only
	ServerAddress  string // plain DNS only
	Encrypted      bool   // true for DoH/DoT — enables OnDemandRules
	IncludeCert    bool
	CertUUID       string
	CertB64        string
	CertIdentifier string
}

var mobileconfigTmpl = template.Must(template.New("mobileconfig").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadDisplayName</key>
	<string>{{.DisplayName}}</string>
	<key>PayloadIdentifier</key>
	<string>{{.Identifier}}</string>
	<key>PayloadScope</key>
	<string>System</string>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>{{.ProfileUUID}}</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadDisplayName</key>
			<string>Blockasaurus DNS ({{.Slug}})</string>
			<key>PayloadIdentifier</key>
			<string>com.blockasaurus.dns.{{.Slug}}.dnsSettings</string>
			<key>PayloadType</key>
			<string>com.apple.dnsSettings.managed</string>
			<key>PayloadUUID</key>
			<string>{{.PayloadUUID}}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
			<key>DNSSettings</key>
			<dict>
{{- if eq .DNSProtocol "HTTPS"}}
				<key>DNSProtocol</key>
				<string>HTTPS</string>
				<key>ServerURL</key>
				<string>{{.ServerURL}}</string>
{{- else if eq .DNSProtocol "TLS"}}
				<key>DNSProtocol</key>
				<string>TLS</string>
				<key>ServerName</key>
				<string>{{.ServerName}}</string>
{{- else}}
				<key>DNSProtocol</key>
				<string>Cleartext</string>
				<key>ServerAddresses</key>
				<array>
					<string>{{.ServerAddress}}</string>
				</array>
{{- end}}
			</dict>
{{- if .Encrypted}}
			<key>OnDemandRules</key>
			<array>
				<dict>
					<key>Action</key>
					<string>Connect</string>
				</dict>
			</array>
{{- end}}
		</dict>
{{- if .IncludeCert}}
		<dict>
			<key>PayloadContent</key>
			<data>{{.CertB64}}</data>
			<key>PayloadDisplayName</key>
			<string>Blockasaurus CA Certificate</string>
			<key>PayloadIdentifier</key>
			<string>{{.CertIdentifier}}</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>{{.CertUUID}}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
{{- end}}
	</array>
</dict>
</plist>
`))

func handleMobileconfig(cfg *config.Config, store *configstore.ConfigStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slug := chi.URLParam(r, "slug")
		if slug == "" {
			http.Error(w, "missing slug", http.StatusBadRequest)

			return
		}

		if _, err := store.GetClientGroupBySlug(slug); err != nil {
			http.NotFound(w, r)

			return
		}

		// Determine protocol and address
		domains := cfg.ClientGroupEndpoints.Domains
		dohPath := cfg.Ports.DOHPath
		hasHTTPS := len(cfg.Ports.HTTPS) > 0
		hasTLS := len(cfg.Ports.TLS) > 0

		var dnsProtocol, serverURL, serverName, serverAddress string

		switch {
		case hasHTTPS && len(domains) > 0:
			dnsProtocol = "HTTPS"
			fqdn := slug + "." + domains[0]
			serverURL = "https://" + fqdn + dohPath
		case hasTLS && len(domains) > 0:
			dnsProtocol = "TLS"
			serverName = slug + "." + domains[0]
		default:
			// Plain DNS — resolve the advertise address
			ip, err := advertise.ResolveAddress(cfg.ClientGroupEndpoints.AdvertiseAddress)
			if err != nil || ip == nil {
				http.Error(w, "no encrypted DNS or advertise address configured", http.StatusServiceUnavailable)

				return
			}
			serverAddress = ip.String()
		}

		// Deterministic UUIDs
		profileUUID := uuid.NewSHA1(mobileconfigNamespace, []byte(slug+".profile"))
		payloadUUID := uuid.NewSHA1(mobileconfigNamespace, []byte(slug+".dnsSettings"))

		data := mobileconfigData{
			DisplayName:   "Blockasaurus DNS (" + slug + ")",
			Identifier:    "com.blockasaurus.dns." + slug,
			ProfileUUID:   profileUUID.String(),
			PayloadUUID:   payloadUUID.String(),
			Slug:          slug,
			DNSProtocol:   dnsProtocol,
			ServerURL:     serverURL,
			ServerName:    serverName,
			ServerAddress: serverAddress,
			Encrypted:     dnsProtocol != "",
		}

		// Optional CA certificate embedding
		if r.URL.Query().Get("includeCert") == "1" && cfg.CertFile != "" {
			certDER, err := extractRootCertDER(cfg.CertFile)
			if err != nil {
				logger().Warnf("mobileconfig: failed to extract root cert: %v", err)
			} else if certDER != nil {
				certUUID := uuid.NewSHA1(mobileconfigNamespace, []byte(slug+".cert"))
				data.IncludeCert = true
				data.CertUUID = certUUID.String()
				data.CertB64 = base64.StdEncoding.EncodeToString(certDER)
				data.CertIdentifier = "com.blockasaurus.dns." + slug + ".cert"
			}
		}

		var buf bytes.Buffer
		if err := mobileconfigTmpl.Execute(&buf, data); err != nil {
			http.Error(w, "template error", http.StatusInternalServerError)
			logger().Errorf("mobileconfig template: %v", err)

			return
		}

		w.Header().Set("Content-Type", "application/x-apple-aspen-config")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="blockasaurus-%s.mobileconfig"`, slug))
		_, _ = w.Write(buf.Bytes())
	}
}

// extractRootCertDER reads a PEM cert file and returns the DER bytes of the
// self-signed root certificate (where Issuer == Subject).
func extractRootCertDER(certFile string) ([]byte, error) {
	pemData, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read cert file: %w", err)
	}

	for {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
			return cert.Raw, nil
		}
	}

	return nil, nil
}

// hasSelfSignedRoot parses a PEM cert file and returns true if the chain
// contains a self-signed certificate (RawIssuer == RawSubject).
func hasSelfSignedRoot(certFile string) bool {
	der, err := extractRootCertDER(certFile)

	return err == nil && der != nil
}
