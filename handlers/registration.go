package handlers

import (
	"context"
	"encoding/json"
	"net/http"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	RegistrationMethod        = http.MethodPost
	RegistrationPattern       = "/machine/register"
	RegistrationLegacyPattern = "/machine/{mkeyhex}"
)

type Registerer interface {
	// RegisterMachine is responsible for registering the machine with the
	// coordinator. It returns the registration response from the coordinator
	// and an error if any.
	RegisterMachine(ctx context.Context, req tailcfg.RegisterRequest, peerPublicKey key.MachinePublic) (tailcfg.RegisterResponse, error)
}

func RegistrationHandler(coordinator Registerer, peerPublicKey key.MachinePublic) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)

		var req tailcfg.RegisterRequest

		err := decoder.Decode(&req)
		if err != nil {
			handleAPIError(w, err, "Failed to decode request body")

			return
		}

		res, err := coordinator.RegisterMachine(r.Context(), req, peerPublicKey)
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
