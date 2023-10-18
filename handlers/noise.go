package handlers

import (
	"errors"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/loft-sh/tunnel"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"tailscale.com/control/controlhttp"
	"tailscale.com/net/netutil"
	"tailscale.com/types/key"
)

const (
	NoiseMethod  = http.MethodPost
	NoisePattern = "/ts2021"
)

func NoiseHandler(coordinator tunnel.TailscaleCoordinator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := controlhttp.AcceptHTTP(r.Context(), w, r, coordinator.ControlKey(), nil)
		if err != nil {
			handleAPIError(w, err, "Failed to accept HTTP connection")

			return
		}

		handler := CreatePeerHandler(coordinator, conn.Peer())

		server := http.Server{}
		server.Handler = h2c.NewHandler(handler, &http2.Server{})

		if err := server.Serve(netutil.NewOneConnListener(conn, nil)); err != nil && !errors.Is(err, io.EOF) {
			handleAPIError(w, err, "Failed to accept HTTP connection")

			return
		}
	}
}

func CreatePeerHandler(coordinator tunnel.TailscaleCoordinator, peerPublicKey key.MachinePublic) http.Handler {
	r := chi.NewMux()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.MethodFunc(RegistrationMethod, RegistrationPattern, RegistrationHandler(coordinator, peerPublicKey))
	r.MethodFunc(PollNetMapMethod, PollNetMapPattern, PollNetMapHandler(coordinator, peerPublicKey))
	r.MethodFunc(SetDNSMethod, SetDNSPattern, SetDNSHandler(coordinator, peerPublicKey))
	r.MethodFunc(HealthChangeMethod, HealthChangePattern, HealthChangeHandler(coordinator, peerPublicKey))
	r.MethodFunc(IDTokenMethod, IDTokenPattern, IDTokenHandler(coordinator, peerPublicKey))
	r.MethodFunc(SSHActionMethod, SSHActionPattern, SSHActionHandler(coordinator, peerPublicKey))

	return r
}
