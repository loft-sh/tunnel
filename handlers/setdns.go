package handlers

import (
	"net/http"

	"github.com/loft-sh/tunnel"
	"tailscale.com/types/key"
)

const (
	SetDNSMethod  = http.MethodPost
	SetDNSPattern = "/machine/set-dns"
)

func SetDNSHandler(coordinator tunnel.TailscaleCoordinator, peerPublicKey key.MachinePublic) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("TODO: Implement SetDNS"))
	}
}
