package mux

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/loft-sh/tunnel"
	"github.com/loft-sh/tunnel/handlers"
)

func CoordinatorHandler(coordinator tunnel.TailscaleCoordinator) http.Handler {
	mux := chi.NewMux()

	mux.MethodFunc(handlers.KeyMethod, handlers.KeyPattern, handlers.KeyHandler(coordinator))
	mux.MethodFunc(handlers.DerpMapMethod, handlers.DerpMapPattern, handlers.DerpMapHandler(coordinator))
	mux.MethodFunc(handlers.NoiseMethod, handlers.NoisePattern, handlers.NoiseHandler(coordinator))

	return mux
}
