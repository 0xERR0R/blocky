// Copyright 2026 Chris Snell
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"net/http"

	"github.com/0xERR0R/blocky/metrics"
	"github.com/0xERR0R/blocky/pkg/statscollector"

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
		case "blockasaurus_query_total":
			total = sumCounter(f.GetMetric())
		case "blockasaurus_response_total":
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
	_ = json.NewEncoder(w).Encode(stats)
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

func handleStatsOvertime(c *statscollector.Collector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"buckets": c.OverTime()})
	}
}

func handleStatsOvertimeClients(c *statscollector.Collector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"buckets": c.OverTime()})
	}
}

func handleStatsOvertimeLatency(c *statscollector.Collector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"buckets": c.OverTime()})
	}
}

func handleStatsQueryTypes(c *statscollector.Collector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(c.QueryTypes())
	}
}

func handleStatsResponseTypes(c *statscollector.Collector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(c.ResponseTypes())
	}
}

func handleStatsTopDomains(c *statscollector.Collector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		permitted, blocked := c.TopDomains(statscollector.DefaultTopN)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"permitted": permitted,
			"blocked":   blocked,
		})
	}
}

func handleStatsTopClients(c *statscollector.Collector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		total, blocked := c.TopClients(statscollector.DefaultTopN)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"total":   total,
			"blocked": blocked,
		})
	}
}
