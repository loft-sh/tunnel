package handlers

import (
	"context"
	"encoding/json"
	"net/http"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	IDTokenMethod  = http.MethodPost
	IDTokenPattern = "/machine/id-token"
)

type IDTokenRequestHandler interface {
	// IDToken handles the ID token request from a tailscale client.
	IDToken(ctx context.Context, req tailcfg.TokenRequest, peerPublicKey key.MachinePublic) (tailcfg.TokenResponse, error)
}

func IDTokenHandler(coordinator IDTokenRequestHandler, peerPublicKey key.MachinePublic) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req tailcfg.TokenRequest

		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			handleAPIError(w, err, "Failed to decode request body")
			return
		}

		res, err := coordinator.IDToken(r.Context(), req, peerPublicKey)
		if err != nil {
			handleAPIError(w, err, "Failed to set DNS")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(res)
	}
}
