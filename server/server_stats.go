package server

import (
	"encoding/json"
	"net/http"

	"github.com/0xERR0R/blocky/metrics"

	dto "github.com/prometheus/client_model/go"
)

type statsResponse struct {
	TotalQueries   float64 `json:"total_queries"`
	BlockedQueries float64 `json:"blocked_queries"`
	BlockRate      float64 `json:"block_rate"`
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	families, err := metrics.Reg.Gather()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var total, blocked float64

	for _, f := range families {
		switch f.GetName() {
		case "blocky_query_total":
			total = sumCounter(f.GetMetric())
		case "blocky_response_total":
			for _, m := range f.GetMetric() {
				if labelValue(m.GetLabel(), "response_type") == "BLOCKED" {
					blocked += m.GetCounter().GetValue()
				}
			}
		}
	}

	stats := statsResponse{
		TotalQueries:   total,
		BlockedQueries: blocked,
	}

	if total > 0 {
		stats.BlockRate = blocked / total * 100
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func sumCounter(ms []*dto.Metric) float64 {
	var sum float64
	for _, m := range ms {
		sum += m.GetCounter().GetValue()
	}

	return sum
}

func labelValue(labels []*dto.LabelPair, name string) string {
	for _, l := range labels {
		if l.GetName() == name {
			return l.GetValue()
		}
	}

	return ""
}
