package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/0xERR0R/blocky/log"
)

const defaultCertPollInterval = 30 * time.Second

// CertProvider polls cert/key files for changes and atomically swaps the certificate.
type CertProvider struct {
	mu           sync.RWMutex
	certFile     string
	keyFile      string
	cert         atomic.Pointer[tls.Certificate]
	lastMod      time.Time
	pollInterval time.Duration
}

// NewCertProvider creates a new CertProvider with the default poll interval.
func NewCertProvider(ctx context.Context, certFile, keyFile string) (*CertProvider, error) {
	return NewCertProviderWithInterval(ctx, certFile, keyFile, defaultCertPollInterval)
}

// NewCertProviderWithInterval creates a new CertProvider with a custom poll interval.
func NewCertProviderWithInterval(
	ctx context.Context, certFile, keyFile string, pollInterval time.Duration,
) (*CertProvider, error) {
	cp := &CertProvider{
		certFile:     certFile,
		keyFile:      keyFile,
		pollInterval: pollInterval,
	}
	if err := cp.loadCert(); err != nil {
		return nil, err
	}
	cp.lastMod = cp.getModTime()
	go cp.poll(ctx)

	return cp, nil
}

// GetCertificate returns the current certificate. Implements tls.Config.GetCertificate.
func (cp *CertProvider) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return cp.cert.Load(), nil
}

func (cp *CertProvider) loadCert() error {
	cp.mu.RLock()
	certFile, keyFile := cp.certFile, cp.keyFile
	cp.mu.RUnlock()

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}

	if len(cert.Certificate) > 0 {
		cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}

	cp.cert.Store(&cert)

	return nil
}

func (cp *CertProvider) getModTime() time.Time {
	cp.mu.RLock()
	files := []string{cp.certFile, cp.keyFile}
	cp.mu.RUnlock()

	var latest time.Time
	for _, f := range files {
		info, err := os.Stat(f)
		if err == nil && info.ModTime().After(latest) {
			latest = info.ModTime()
		}
	}

	return latest
}

func (cp *CertProvider) poll(ctx context.Context) {
	ticker := time.NewTicker(cp.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			mod := cp.getModTime()

			cp.mu.RLock()
			last := cp.lastMod
			cp.mu.RUnlock()

			if mod.After(last) {
				cp.mu.Lock()
				cp.lastMod = mod
				cp.mu.Unlock()

				if err := cp.loadCert(); err != nil {
					log.PrefixedLog("server").Error("TLS certificate reload failed: ", err)
				} else {
					log.PrefixedLog("server").Info("TLS certificate reloaded")
				}
			}
		}
	}
}

// UpdatePaths updates the cert/key file paths and forces a reload on the next poll.
func (cp *CertProvider) UpdatePaths(certFile, keyFile string) {
	cp.mu.Lock()
	cp.certFile = certFile
	cp.keyFile = keyFile
	cp.lastMod = time.Time{} // force reload on next poll
	cp.mu.Unlock()
}
