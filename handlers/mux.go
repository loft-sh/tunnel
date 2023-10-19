package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/loft-sh/tunnel"
)

// CoordinatorHandler returns a http.Handler that handles all requests to the
// coordinator, including the noise requests.
func CoordinatorHandler(coordinator tunnel.TailscaleCoordinator) http.Handler {
	mux := chi.NewMux()

	mux.MethodFunc(KeyMethod, KeyPattern, KeyHandler(coordinator))
	mux.MethodFunc(DerpMapMethod, DerpMapPattern, DerpMapHandler(coordinator))
	mux.MethodFunc(NoiseMethod, NoisePattern, NoiseHandler(coordinator))

	return mux
}
