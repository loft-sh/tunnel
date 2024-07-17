package handlers

import (
	"context"
	"encoding/json"
	"net/http"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	HealthChangeMethod  = http.MethodPost
	HealthChangePattern = "/machine/health-change"
)

type HealthChanger interface {
	// HealthChange handles the health change request from a tailscale client.
	HealthChange(ctx context.Context, req tailcfg.HealthChangeRequest)
}

func HealthChangeHandler(coordinator HealthChanger, peerPublicKey key.MachinePublic) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req tailcfg.HealthChangeRequest

		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			handleAPIError(w, err, "Failed to decode request body")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		coordinator.HealthChange(r.Context(), req)
	}
}
