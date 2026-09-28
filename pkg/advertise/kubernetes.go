package advertise

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

const (
	saTokenPath     = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	saNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

// detectKubernetesIP queries the k8s API for a LoadBalancer Service with port 53
// in the pod's namespace, labeled with app.kubernetes.io/name=blockasaurus.
func detectKubernetesIP() (net.IP, error) {
	token, err := os.ReadFile(saTokenPath)
	if err != nil {
		return nil, fmt.Errorf("read service account token: %w", err)
	}

	ns, err := os.ReadFile(saNamespacePath)
	if err != nil {
		return nil, fmt.Errorf("read namespace: %w", err)
	}

	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")

	if port == "" {
		port = "443"
	}

	url := fmt.Sprintf(
		"https://%s/api/v1/namespaces/%s/services?labelSelector=app.kubernetes.io/name=blockasaurus",
		net.JoinHostPort(host, port), string(ns),
	)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			// #nosec G402 -- in-cluster API server uses a self-signed CA; the SA token authenticates the request
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+string(token))

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("k8s API request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))

		return nil, fmt.Errorf("k8s API returned %d: %s", resp.StatusCode, string(body))
	}

	return parseServiceListForLBIP(resp.Body)
}

func parseServiceListForLBIP(r io.Reader) (net.IP, error) {
	var svcList struct {
		Items []struct {
			Spec struct {
				Ports []struct {
					Port int `json:"port"`
				} `json:"ports"`
			} `json:"spec"`
			Status struct {
				LoadBalancer struct {
					Ingress []struct {
						IP string `json:"ip"`
					} `json:"ingress"`
				} `json:"loadBalancer"`
			} `json:"status"`
		} `json:"items"`
	}

	if err := json.NewDecoder(r).Decode(&svcList); err != nil {
		return nil, fmt.Errorf("decode service list: %w", err)
	}

	// Find first service with port 53 and a LB ingress IP
	for _, svc := range svcList.Items {
		hasDNSPort := false
		for _, p := range svc.Spec.Ports {
			if p.Port == 53 {
				hasDNSPort = true

				break
			}
		}

		if !hasDNSPort {
			continue
		}

		for _, ing := range svc.Status.LoadBalancer.Ingress {
			if ip := net.ParseIP(ing.IP); ip != nil {
				return ip, nil
			}
		}
	}

	return nil, errors.New("no LoadBalancer service with port 53 and external IP found")
}
