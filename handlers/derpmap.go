package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/loft-sh/tunnel"
)

const (
	DerpMapMethod  = http.MethodGet
	DerpMapPattern = "/derpmap/default"
)

func DerpMapHandler(coordinator tunnel.TailscaleCoordinator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		res, err := coordinator.DerpMap()
		if err != nil {
			handleAPIError(w, err, "Failed to get derp map")

			return
		}

		_ = json.NewEncoder(w).Encode(res)
	}
}
