package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/loft-sh/tunnel"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	RegistrationMethod        = http.MethodPost
	RegistrationPattern       = "/machine/register"
	RegistrationLegacyPattern = "/machine/{mkeyhex}"
)

func RegistrationHandler(coordinator tunnel.Coordinator, peerPublicKey key.MachinePublic) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)

		var req tailcfg.RegisterRequest

		err := decoder.Decode(&req)
		if err != nil {
			handleAPIError(w, err, "Failed to decode request body")

			return
		}

		res, err := coordinator.RegisterMachine(req, peerPublicKey)
		if err != nil {
			res = tailcfg.RegisterResponse{
				Error: err.Error(),
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(res)
	}
}
