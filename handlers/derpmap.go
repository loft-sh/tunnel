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

func DerpMapHandler(coordinator tunnel.Coordinator) http.HandlerFunc {
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
