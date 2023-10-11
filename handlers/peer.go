package handlers

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jba/muxpatterns"
	"github.com/loft-sh/tunnel"
	"tailscale.com/types/key"
)

func CreatePeerHandler(coordinator tunnel.TailscaleCoordinator, peerPublicKey key.MachinePublic) http.Handler {
	mux := muxpatterns.NewServeMux()
	mux.HandleFunc(fmt.Sprintf("%s %s", RegistrationMethod, RegistrationPattern), RegistrationHandler(coordinator, peerPublicKey))
	mux.HandleFunc(fmt.Sprintf("%s %s", PollNetMapMethod, PollNetMapPattern), PollNetMapHandler(coordinator, peerPublicKey))
	mux.HandleFunc(fmt.Sprintf("%s %s", SetDNSMethod, SetDNSPattern), SetDNSHandler(coordinator, peerPublicKey))
	mux.HandleFunc(fmt.Sprintf("%s %s", HealthChangeMethod, HealthChangePattern), HealthChangeHandler(coordinator, peerPublicKey))
	mux.HandleFunc(fmt.Sprintf("%s %s", IDTokenMethod, IDTokenPattern), IDTokenHandler(coordinator, peerPublicKey))

	return mux
}

func CreateChiPeerHandler(coordinator tunnel.TailscaleCoordinator, peerPublicKey key.MachinePublic) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.MethodFunc(RegistrationMethod, RegistrationPattern, RegistrationHandler(coordinator, peerPublicKey))
	r.MethodFunc(PollNetMapMethod, PollNetMapPattern, PollNetMapHandler(coordinator, peerPublicKey))
	r.MethodFunc(SetDNSMethod, SetDNSPattern, SetDNSHandler(coordinator, peerPublicKey))
	r.MethodFunc(HealthChangeMethod, HealthChangePattern, HealthChangeHandler(coordinator, peerPublicKey))
	r.MethodFunc(IDTokenMethod, IDTokenPattern, IDTokenHandler(coordinator, peerPublicKey))

	return r
}
