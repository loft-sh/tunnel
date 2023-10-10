package handlers

import (
	"fmt"
	"net/http"

	"github.com/jba/muxpatterns"
	"github.com/loft-sh/tunnel"
	"tailscale.com/types/key"
)

func CreatePeerHandler(coordinator tunnel.TailscaleCoordinator, peerPublicKey key.MachinePublic) http.Handler {
	mux := muxpatterns.NewServeMux()

	mux.HandleFunc(fmt.Sprintf("%s %s", RegistrationMethod, RegistrationPattern), RegistrationHandler(coordinator, peerPublicKey))
	mux.HandleFunc(fmt.Sprintf("%s %s", PollNetMapMethod, PollNetMapPattern), PollNetMapHandler(coordinator, peerPublicKey))
	mux.HandleFunc(fmt.Sprintf("%s %s", SetDNSMethod, SetDNSPattern), SetDNSHandler(coordinator, peerPublicKey))
	mux.HandleFunc(fmt.Sprintf("%s %s", IDTokenMethod, IDTokenPattern), IDTokenHandler(coordinator, peerPublicKey))
	mux.HandleFunc(fmt.Sprintf("%s %s", SSHActionAuthStartMethod, SSHActionAuthStartPattern), SSHActionAuthStartHandler(coordinator, peerPublicKey))
	mux.HandleFunc(fmt.Sprintf("%s %s", SSHActionAuthCheckMethod, SSHActionAuthCheckPattern), SSHActionAuthCheckHandler(coordinator, peerPublicKey))

	return mux
}
