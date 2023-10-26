package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/loft-sh/tunnel"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	HealthChangeMethod  = http.MethodPost
	HealthChangePattern = "/machine/health-change"
)

func HealthChangeHandler(coordinator tunnel.Coordinator, peerPublicKey key.MachinePublic) http.HandlerFunc {
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
