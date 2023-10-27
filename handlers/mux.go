package handlers

import (
	"net/http"
	"os"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/loft-sh/tunnel"
)

var ShouldLogRequest = os.Getenv("LOG_NOISE_REQUEST") == "true"

// CoordinatorHandler returns a http.Handler that handles all requests to the
// coordinator, including the noise requests.
func CoordinatorHandler(coordinator tunnel.Coordinator) http.Handler {
	return CoordinatorHandlerWithSubpath(coordinator, "/")
}

// CoordinatorHandlerWithSubpath returns a http.Handler that handles all
// requests to the coordinator, including the noise requests.
// The subPath is the path at which the handlers will be mounted.
func CoordinatorHandlerWithSubpath(coordinator tunnel.Coordinator, subPath string) http.Handler {
	subPath = strings.TrimSuffix(subPath, "/")

	if subPath == "" {
		subPath = "/"
	}

	mux := chi.NewMux()

	if ShouldLogRequest {
		mux.Use(middleware.Logger)
	}

	mux.Use(middleware.Recoverer)

	mux.MethodFunc(KeyMethod, KeyPattern, KeyHandler(coordinator))
	mux.MethodFunc(DerpMapMethod, DerpMapPattern, DerpMapHandler(coordinator))
	mux.MethodFunc(NoiseMethod, NoisePattern, NoiseHandler(coordinator, subPath))

	if subPath != "/" {
		return http.StripPrefix(subPath, mux)
	}

	return mux
}
