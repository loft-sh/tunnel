package tunnel

import (
	"github.com/loft-sh/tunnel/handlers"
)

// BareCoordinator is an interface encorfcing the bare handlers that need to be
// defined for the Tailscale control server to work.
type BareCoordinator = handlers.Coordinator

// Coordinator is the interface enforcing all handler functions to be defined.
type Coordinator interface {
	BareCoordinator

	handlers.DNSSetter
	handlers.HealthChanger
	handlers.IDTokenRequestHandler
	handlers.SSHActioner
}
