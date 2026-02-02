package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"riskmgt/database"
)

// HealthCheckResponse represents health check status
type HealthCheckResponse struct {
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
	Database  string    `json:"database,omitempty"`
	Version   string    `json:"version"`
	Uptime    string    `json:"uptime,omitempty"`
}

var startTime = time.Now()

// HealthCheck handles health check requests
func HealthCheck(w http.ResponseWriter, r *http.Request) {
	response := HealthCheckResponse{
		Status:    "healthy",
		Timestamp: time.Now().UTC(),
		Version:   "1.0.0",
		Uptime:    time.Since(startTime).String(),
	}

	// Check MongoDB connection if available
	if database.Client != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		
		if err := database.Client.Ping(ctx, nil); err != nil {
			response.Status = "unhealthy"
			response.Database = "disconnected"
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			response.Database = "connected"
		}
	}

	w.Header().Set("Content-Type", "application/json")
	
	if response.Status == "unhealthy" {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	
	json.NewEncoder(w).Encode(response)
}