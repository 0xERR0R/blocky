package advertise

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseServiceListForLBIP_Found(t *testing.T) {
	body := `{
		"items": [{
			"spec": {"ports": [{"port": 53}]},
			"status": {"loadBalancer": {"ingress": [{"ip": "10.50.0.231"}]}}
		}]
	}`

	ip, err := parseServiceListForLBIP(strings.NewReader(body))
	require.NoError(t, err)
	assert.Equal(t, "10.50.0.231", ip.String())
}

func TestParseServiceListForLBIP_NoDNSPort(t *testing.T) {
	body := `{
		"items": [{
			"spec": {"ports": [{"port": 80}]},
			"status": {"loadBalancer": {"ingress": [{"ip": "10.50.0.231"}]}}
		}]
	}`

	_, err := parseServiceListForLBIP(strings.NewReader(body))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no LoadBalancer service")
}

func TestParseServiceListForLBIP_NoIngress(t *testing.T) {
	body := `{
		"items": [{
			"spec": {"ports": [{"port": 53}]},
			"status": {"loadBalancer": {"ingress": []}}
		}]
	}`

	_, err := parseServiceListForLBIP(strings.NewReader(body))
	require.Error(t, err)
}

func TestParseServiceListForLBIP_Empty(t *testing.T) {
	body := `{"items": []}`

	_, err := parseServiceListForLBIP(strings.NewReader(body))
	require.Error(t, err)
}

func TestParseServiceListForLBIP_MultipleServices(t *testing.T) {
	body := `{
		"items": [
			{
				"spec": {"ports": [{"port": 80}]},
				"status": {"loadBalancer": {"ingress": [{"ip": "10.0.0.1"}]}}
			},
			{
				"spec": {"ports": [{"port": 53}]},
				"status": {"loadBalancer": {"ingress": [{"ip": "10.50.0.231"}]}}
			}
		]
	}`

	ip, err := parseServiceListForLBIP(strings.NewReader(body))
	require.NoError(t, err)
	assert.Equal(t, "10.50.0.231", ip.String())
}
