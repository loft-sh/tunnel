package tunnel

import (
	"context"
	"net/http"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type TailscaleCoordinator interface {
	ControlKey() key.MachinePrivate
	LegacyControlKey() key.MachinePrivate

	RegisterMachine(req tailcfg.RegisterRequest, peerPublicKey key.MachinePublic) (tailcfg.RegisterResponse, error)

	DerpMap() (tailcfg.DERPMap, error)

	KeepAliveInterval() time.Duration
	PollNetMap(ctx context.Context, req tailcfg.MapRequest, peerPublicKey key.MachinePublic) (chan tailcfg.MapResponse, chan error)

	SetDNS(req tailcfg.SetDNSRequest, peerPublicKey key.MachinePublic) (tailcfg.SetDNSResponse, error)

	HealthChange(req tailcfg.HealthChangeRequest)

	IDToken(req tailcfg.TokenRequest, peerPublicKey key.MachinePublic) (tailcfg.TokenResponse, error)

	SSHAction(r *http.Request, peerPublicKey key.MachinePublic) (tailcfg.SSHAction, error)
}
