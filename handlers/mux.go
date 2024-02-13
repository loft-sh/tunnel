package handlers

import (
	"net/http"
	"strings"

	"github.com/loft-sh/tunnel"
)

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

	mux := http.NewServeMux()

	mux.HandleFunc(KeyMethod+" "+KeyPattern, KeyHandler(coordinator))
	mux.HandleFunc(DerpMapMethod+" "+DerpMapPattern, DerpMapHandler(coordinator))
	mux.HandleFunc(NoiseMethod+" "+NoisePattern, NoiseHandler(coordinator, subPath))

	if subPath != "/" {
		return http.StripPrefix(subPath, mux)
	}

	return mux
}
