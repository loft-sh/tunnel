package handlers

import (
	"encoding/json"
	"net/http"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	SSHActionMethod  = http.MethodGet
	SSHActionPattern = "/ssh/action/*"
)

type SSHActioner interface {
	// SSHAction handles the SSH action request from a tailscale client.
	//
	// It returns the SSH action response and an error if any. Additionally, the
	// entire request is provided to the implementation as the request may
	// contain additional information that is not known to the library.
	//
	// This method handles all noise requests to the `/ssh/action/*` pattern.
	SSHAction(r *http.Request, peerPublicKey key.MachinePublic) (tailcfg.SSHAction, error)
}

func SSHActionHandler(coordinator SSHActioner, peerPublicKey key.MachinePublic) http.HandlerFunc {
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
