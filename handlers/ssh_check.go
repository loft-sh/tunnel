package handlers

import (
	"net/http"

	"github.com/loft-sh/tunnel"
	"tailscale.com/types/key"
)

const (
	SSHActionAuthCheckMethod  = http.MethodGet
	SSHActionAuthCheckPattern = "/machine/ssh/action/check/to/{key}"
)

func SSHActionAuthCheckHandler(coordinator tunnel.TailscaleCoordinator, peerPublicKey key.MachinePublic) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("TODO: Implement SSHActionAuthCheck"))
	}
}
