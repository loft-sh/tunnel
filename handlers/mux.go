package handlers

import (
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/loft-sh/tunnel"
)

var ShouldLogRequest = os.Getenv("LOG_NOISE_REQUEST") == "true"

// CoordinatorHandler returns a http.Handler that handles all requests to the
// coordinator, including the noise requests.
func CoordinatorHandler(coordinator tunnel.Coordinator) http.Handler {
	mux := chi.NewMux()

	if ShouldLogRequest {
		mux.Use(middleware.Logger)
	}

	mux.Use(middleware.Recoverer)

	mux.MethodFunc(KeyMethod, KeyPattern, KeyHandler(coordinator))
	mux.MethodFunc(DerpMapMethod, DerpMapPattern, DerpMapHandler(coordinator))
	mux.MethodFunc(NoiseMethod, NoisePattern, NoiseHandler(coordinator))

	return mux
}
