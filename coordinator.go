package tunnel

import (
	"context"
	"net/http"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// Coordinator is the interface that wraps the coordinator methods.
type Coordinator interface {
	// ControlKey returns the control key for coordinator.
	ControlKey() key.MachinePrivate
	// LegacyControlKey returns the legacy control key for coordinator.
	LegacyControlKey() key.MachinePrivate

	// RegisterMachine is responsible for registering the machine with the
	// coordinator. It returns the registration response from the coordinator
	// and an error if any.
	RegisterMachine(ctx context.Context, req tailcfg.RegisterRequest, peerPublicKey key.MachinePublic) (tailcfg.RegisterResponse, error)

	// DerpMap returns the DERP map from the coordinator.
	DerpMap(ctx context.Context) (tailcfg.DERPMap, error)

	// KeepAliveInterval is the keep alive interval used by the coordinator to
	// periodically send keep alive messages to the tailscale client via the
	// long poll NetMap request.
	KeepAliveInterval() time.Duration
	// PollNetMap handles the netmap polling request from a tailscale client. It
	// returns a channel of netmap responses and a channel of errors.
	//
	// - If the request is a streaming one, the channels are not to be closed
	// and new responses shall be sent via the channels.
	//
	// - If the request is a non-streaming one, the channels are to be closed
	// after the first response is sent.
	//
	// - If the request gets closed or cancelled by the tailscale client, the
	// context will be cancelled and the channels shall not be used anymore.
	PollNetMap(ctx context.Context, req tailcfg.MapRequest, peerPublicKey key.MachinePublic) (chan tailcfg.MapResponse, chan error)

	// SetDNS handles the DNS setting request from a tailscale client.
	SetDNS(ctx context.Context, req tailcfg.SetDNSRequest, peerPublicKey key.MachinePublic) (tailcfg.SetDNSResponse, error)

	// HealthChange handles the health change request from a tailscale client.
	HealthChange(ctx context.Context, req tailcfg.HealthChangeRequest)

	// IDToken handles the ID token request from a tailscale client.
	IDToken(ctx context.Context, req tailcfg.TokenRequest, peerPublicKey key.MachinePublic) (tailcfg.TokenResponse, error)

	// SSHAction handles the SSH action request from a tailscale client.
	//
	// It returns the SSH action response and an error if any. Additionally, the
	// entire request is provided to the implementation as the request may
	// contain additional information that is not known to the library.
	//
	// This method handles all noise requests to the `/ssh/action/*` pattern.
	SSHAction(r *http.Request, peerPublicKey key.MachinePublic) (tailcfg.SSHAction, error)
}
