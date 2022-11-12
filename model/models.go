package model

//go:generate go run github.com/abice/go-enum -f=$GOFILE --marshal --names
import (
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// ResponseType represents the type of the response ENUM(
// RESOLVED // the response was resolved by the external upstream resolver
// CACHED // the response was resolved from cache
// BLOCKED // the query was blocked
// CONDITIONAL // the query was resolved by the conditional upstream resolver
// CUSTOMDNS // the query was resolved by a custom rule
// HOSTSFILE // the query was resolved by looking up the hosts file
// FILTERED // the query was filtered by query type
// NOTFQDN // the query was filtered as it is not fqdn conform
// SPECIAL // the query was resolved by the special use domain name resolver
// )
type ResponseType int

// Response represents the response of a DNS query
type Response struct {
	Res    *dns.Msg
	Reason string
	RType  ResponseType
}

// RequestProtocol represents the server protocol ENUM(
// TCP // is the TCP protocol
// UDP // is the UDP protocol
// )
type RequestProtocol uint8

// Request represents client's DNS request
type Request struct {
	ClientIP        net.IP
	RequestClientID string
	Protocol        RequestProtocol
	ClientNames     []string
	Req             *dns.Msg
	Log             *logrus.Entry
	RequestTS       time.Time
}
