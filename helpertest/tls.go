package helpertest

import (
	"crypto/tls"
	"crypto/x509"
	"sync"

	"github.com/0xERR0R/blocky/util"
	. "github.com/onsi/gomega"
)

const tlsTestServerName = "test.blocky.invalid"

type tlsData struct {
	ServerCfg *tls.Config
	ClientCfg *tls.Config
}

// Lazy init
//
//nolint:gochecknoglobals
var (
	initTLSData    sync.Once
	tlsDataStorage tlsData
)

func getTLSData() tlsData {
	initTLSData.Do(func() {
		cert, err := util.TLSGenerateSelfSignedCert([]string{tlsTestServerName})
		Expect(err).Should(Succeed())

		tlsDataStorage.ServerCfg = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}

		certPool := x509.NewCertPool()
		certPool.AddCert(cert.Leaf)

		tlsDataStorage.ClientCfg = &tls.Config{
			RootCAs:    certPool,
			ServerName: tlsTestServerName,
			MinVersion: tls.VersionTLS13,
		}
	})

	return tlsDataStorage
}

// TLSTestServerConfig returns a TLS Config for use by test servers.
func TLSTestServerConfig() *tls.Config {
	return getTLSData().ServerCfg.Clone()
}

// TLSTestServerConfig returns a TLS Config for use by test clients.
//
// This is required to connect to a test TLS server, otherwise TLS verification fails.
func TLSTestClientConfig() *tls.Config {
	return getTLSData().ClientCfg.Clone()
}
