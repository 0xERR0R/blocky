package model

//go:generate go-enum -f=$GOFILE --marshal --names
import (
	"encoding/json"
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
// )
type ResponseType int

// Response represents the response of a DNS query
type Response struct {
	Res    *dns.Msg
	Reason string
	RType  ResponseType
}

// RequestProtocol represents the server protocol ENUM(
// TCP // is the TPC protocol
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

// ResponseCache struct holding key and response for cache synchronization
type ResponseCache struct {
	Key      string
	Response *Response
}

// MarshalBinary encodes the struct to json
func (u *ResponseCache) MarshalBinary() ([]byte, error) {
	return json.Marshal(u)
}

// UnmarshalBinary decodes the struct into a CacheMessage
func (u *ResponseCache) UnmarshalBinary(data []byte) error {
	err := json.Unmarshal(data, &u)

	return err
}
