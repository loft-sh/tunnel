package mux

import (
	"fmt"
	"net/http"

	"github.com/jba/muxpatterns"
	"github.com/loft-sh/tunnel"
	"github.com/loft-sh/tunnel/handlers"
)

func CoordinatorHandler(coordinator tunnel.TailscaleCoordinator) http.Handler {
	mux := muxpatterns.NewServeMux()

	mux.HandleFunc(fmt.Sprintf("%s %s", handlers.KeyMethod, handlers.KeyPattern), handlers.KeyHandler(coordinator))
	mux.HandleFunc(fmt.Sprintf("%s %s", handlers.NoiseMethod, handlers.NoisePattern), handlers.NoiseHandler(coordinator))

	return mux
}
