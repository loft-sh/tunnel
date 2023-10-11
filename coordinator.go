package tunnel

import (
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type TailscaleCoordinator interface {
	ControlKey() key.MachinePrivate
	LegacyControlKey() key.MachinePrivate

	RegisterMachine(req tailcfg.RegisterRequest, peerPublicKey key.MachinePublic) (tailcfg.RegisterResponse, error)

	DerpMap() (tailcfg.DERPMap, error)

	SyncInterval() time.Duration
	KeepAliveInterval() time.Duration
	PollNetMap(req tailcfg.MapRequest, peerPublicKey key.MachinePublic, delta bool) (tailcfg.MapResponse, error)
}
