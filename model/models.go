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
	Key    string
	Res    []byte
	Reason string
	RType  ResponseType
}

func (r *Response) ConvertToCache(key string) (*ResponseCache, error) {
	res := r.Res
	res.Compress = true

	resBin, err := res.Pack()
	if err == nil {
		result := &ResponseCache{
			Key:    key,
			Res:    resBin,
			Reason: r.Reason,
			RType:  r.RType,
		}

		return result, nil
	}

	return nil, err
}

func (rc *ResponseCache) ConvertFromCache() (string, *Response, error) {
	res := &dns.Msg{}

	err := res.Unpack(rc.Res)
	if err == nil {
		result := &Response{
			Res:    res,
			Reason: rc.Reason,
			RType:  rc.RType,
		}

		return rc.Key, result, nil
	}

	return rc.Key, nil, err
}

// MarshalBinary encodes the struct to json
func (rc *ResponseCache) MarshalBinary() ([]byte, error) {
	return json.Marshal(rc)
}

// UnmarshalString decodes string to struct
func (rc *ResponseCache) UnmarshalString(data string) error {
	return json.Unmarshal([]byte(data), &rc)
}
