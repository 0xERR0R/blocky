package model

import (
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// ResponseType represents the type of the response
type ResponseType int

const (
	// RESOLVED the response was resolved by the external upstream resolver
	RESOLVED ResponseType = iota

	// CACHED the response was resolved from cache
	CACHED

	// BLOCKED the query was blocked
	BLOCKED

	// CONDITIONAL the query was resolved by the conditional upstream resolver
	CONDITIONAL

	// CUSTOMDNS the query was resolved by a custom rule
	CUSTOMDNS
)

func (r ResponseType) String() string {
	names := [...]string{
		"RESOLVED",
		"CACHED",
		"BLOCKED",
		"CONDITIONAL",
		"CUSTOMDNS"}

	return names[r]
}

// Response represents the response of a DNS query
type Response struct {
	Res    *dns.Msg
	Reason string
	RType  ResponseType
}

// RequestProtocol represents the server protocol
type RequestProtocol uint8

const (
	// TCP is the TPC protocol
	TCP RequestProtocol = iota

	// UDP is the UDP protocol
	UDP
)

func (r RequestProtocol) String() string {
	names := [...]string{
		"TCP",
		"UDP"}

	return names[r]
}

// Request represents client's DNS request
type Request struct {
	ClientIP    net.IP
	Protocol    RequestProtocol
	ClientNames []string
	Req         *dns.Msg
	Log         *logrus.Entry
	RequestTS   time.Time
}
