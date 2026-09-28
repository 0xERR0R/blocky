package advertise

import (
	"net"
	"testing"

	"github.com/0xERR0R/blocky/config"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveAddress_Empty(t *testing.T) {
	ip, err := ResolveAddress("")
	require.NoError(t, err)
	assert.Nil(t, ip)
}

func TestResolveAddress_ExplicitIPv4(t *testing.T) {
	ip, err := ResolveAddress("10.50.0.231")
	require.NoError(t, err)
	assert.Equal(t, net.ParseIP("10.50.0.231").To4(), ip.To4())
}

func TestResolveAddress_ExplicitIPv6(t *testing.T) {
	ip, err := ResolveAddress("::1")
	require.NoError(t, err)
	assert.Equal(t, net.ParseIP("::1"), ip)
}

func TestResolveAddress_Invalid(t *testing.T) {
	_, err := ResolveAddress("not-an-ip")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid advertiseAddress")
}

func TestResolveAddress_AutoOutbound(t *testing.T) {
	// "auto" without KUBERNETES_SERVICE_HOST falls back to outbound detection
	t.Setenv("KUBERNETES_SERVICE_HOST", "")

	ip, err := ResolveAddress("auto")
	require.NoError(t, err)
	assert.NotNil(t, ip)
	assert.False(t, ip.IsLoopback())
	assert.False(t, ip.IsUnspecified())
}

func TestInjectRecords_SingleDomain(t *testing.T) {
	mapping := make(config.CustomDNSMapping)
	ip := net.ParseIP("10.50.0.231")

	InjectRecords(mapping, []string{"dns.example.com"}, ip, 3600)

	assert.Contains(t, mapping, "dns.example.com.")
	assert.Contains(t, mapping, "*.dns.example.com.")
	assert.Len(t, mapping, 2)

	// Verify A record
	rr := mapping["dns.example.com."][0]
	a, ok := rr.(*dns.A)
	require.True(t, ok)
	assert.Equal(t, ip.To4(), a.A)
	assert.Equal(t, uint32(3600), a.Hdr.Ttl)
}

func TestInjectRecords_MultipleDomains(t *testing.T) {
	mapping := make(config.CustomDNSMapping)
	ip := net.ParseIP("192.168.1.5")

	InjectRecords(mapping, []string{"dns.example.com", "blockasaurus.local"}, ip, 3600)

	assert.Len(t, mapping, 4)
	assert.Contains(t, mapping, "dns.example.com.")
	assert.Contains(t, mapping, "*.dns.example.com.")
	assert.Contains(t, mapping, "blockasaurus.local.")
	assert.Contains(t, mapping, "*.blockasaurus.local.")
}

func TestInjectRecords_IPv6(t *testing.T) {
	mapping := make(config.CustomDNSMapping)
	ip := net.ParseIP("fd00::1")

	InjectRecords(mapping, []string{"dns.example.com"}, ip, 3600)

	rr := mapping["dns.example.com."][0]
	aaaa, ok := rr.(*dns.AAAA)
	require.True(t, ok)
	assert.Equal(t, net.ParseIP("fd00::1"), aaaa.AAAA)
}

func TestInjectRecords_SkipsExisting(t *testing.T) {
	mapping := make(config.CustomDNSMapping)

	// Pre-populate with a user-defined entry
	mapping["dns.example.com."] = config.CustomDNSEntries{&dns.A{
		Hdr: dns.RR_Header{Name: "dns.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("1.2.3.4").To4(),
	}}

	InjectRecords(mapping, []string{"dns.example.com"}, net.ParseIP("10.50.0.231"), 3600)

	// Base domain should keep user-defined entry
	a := mapping["dns.example.com."][0].(*dns.A)
	assert.Equal(t, net.ParseIP("1.2.3.4").To4(), a.A)

	// Wildcard should be auto-injected since it wasn't pre-existing
	assert.Contains(t, mapping, "*.dns.example.com.")
}

func TestDetectOutboundIP(t *testing.T) {
	ip, err := detectOutboundIP()
	require.NoError(t, err)
	assert.NotNil(t, ip)
	assert.False(t, ip.IsLoopback())
	assert.False(t, ip.IsUnspecified())
}
