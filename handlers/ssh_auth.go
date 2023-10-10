package handlers

import (
	"net/http"

	"github.com/loft-sh/tunnel"
	"tailscale.com/types/key"
)

const (
	SSHActionAuthStartMethod  = http.MethodGet
	SSHActionAuthStartPattern = "/machine/ssh/action/{src_machine_id}/to/{dst_machine_id}"
)

func SSHActionAuthStartHandler(coordinator tunnel.TailscaleCoordinator, peerPublicKey key.MachinePublic) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("TODO: Implement SSHActionAuthStart"))
	}
}
