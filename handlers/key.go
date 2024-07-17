package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	NoiseCapabilityVersion = 28
)

const (
	KeyMethod  = http.MethodGet
	KeyPattern = "/key"
)

type Keyer interface {
	// ControlKey returns the control key for coordinator.
	ControlKey() key.MachinePrivate
	// LegacyControlKey returns the legacy control key for coordinator.
	LegacyControlKey() key.MachinePrivate
}

func KeyHandler(coordinator Keyer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("v")

		if v != "" {
			clientCapabilityVersion, err := strconv.Atoi(v)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte("Invalid version"))

				return
			}

			if clientCapabilityVersion >= NoiseCapabilityVersion {
				keys := &tailcfg.OverTLSPublicKeyResponse{
					LegacyPublicKey: coordinator.LegacyControlKey().Public(),
					PublicKey:       coordinator.ControlKey().Public(),
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(keys)

				return
			}
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(coordinator.LegacyControlKey().Public().String()))
	}
}
