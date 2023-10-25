package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/loft-sh/tunnel"
	"tailscale.com/types/key"
)

const (
	SSHActionMethod  = http.MethodGet
	SSHActionPattern = "/ssh/action/*"
)

func SSHActionHandler(coordinator tunnel.Coordinator, peerPublicKey key.MachinePublic) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		res, err := coordinator.SSHAction(r, peerPublicKey)
		if err != nil {
			handleAPIError(w, err, "Failed to start SSH action")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(res)
	}
}
