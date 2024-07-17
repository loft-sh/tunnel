package handlers

import (
	"context"
	"encoding/json"
	"net/http"

	"tailscale.com/tailcfg"
)

const (
	DerpMapMethod  = http.MethodGet
	DerpMapPattern = "/derpmap/default"
)

type DerpMapper interface {
	// DerpMap returns the DERP map from the coordinator.
	DerpMap(ctx context.Context) (tailcfg.DERPMap, error)
}

func DerpMapHandler(coordinator DerpMapper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		res, err := coordinator.DerpMap(r.Context())
		if err != nil {
			handleAPIError(w, err, "Failed to get derp map")

			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(res)
	}
}
