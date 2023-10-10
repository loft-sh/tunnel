package main

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/loft-sh/tunnel"
	"github.com/loft-sh/tunnel/mux"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func main() {
	r := chi.NewRouter()

	r.Use(middleware.Logger)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("welcome"))
	})

	coordinator := NewTSCoordinator()
	r.Handle("/*", mux.CoordinatorHandler(coordinator))

	if err := http.ListenAndServe(":3000", r); err != nil {
		panic(err)
	}
}

type TSCoordinator struct {
	controlKey        key.MachinePrivate
	legacyControlKey  key.MachinePrivate
	keepAliveInterval time.Duration
	syncInterval      time.Duration
}

// KeepAliveInterval implements tunnel.TailscaleCoordinator.
func (t *TSCoordinator) KeepAliveInterval() time.Duration {
	return t.keepAliveInterval
}

// SyncInterval implements tunnel.TailscaleCoordinator.
func (t *TSCoordinator) SyncInterval() time.Duration {
	return t.syncInterval
}

// PollNetMap implements tunnel.TailscaleCoordinator.
func (*TSCoordinator) PollNetMap(req tailcfg.MapRequest, peerPublicKey key.MachinePublic) (tailcfg.MapResponse, error) {
	now := time.Now()

	return tailcfg.MapResponse{
		MapSessionHandle: req.MapSessionHandle,
		ControlTime:      &now,
		KeepAlive:        true,
	}, nil
}

// RegisterMachine implements tunnel.TailscaleCoordinator.
func (*TSCoordinator) RegisterMachine(req tailcfg.RegisterRequest, peerPublicKey key.MachinePublic) (tailcfg.RegisterResponse, error) {
	return tailcfg.RegisterResponse{
		MachineAuthorized: true,
	}, nil
}

// ControlKey implements tunnel.TailscaleCoordinator.
func (t *TSCoordinator) ControlKey() key.MachinePrivate {
	return t.controlKey
}

// LegacyControlKey implements tunnel.TailscaleCoordinator.
func (t *TSCoordinator) LegacyControlKey() key.MachinePrivate {
	return t.legacyControlKey
}

func NewTSCoordinator() *TSCoordinator {
	return &TSCoordinator{
		controlKey:        key.NewMachine(),
		legacyControlKey:  key.NewMachine(),
		keepAliveInterval: 60 * time.Second,
		syncInterval:      30 * time.Second,
	}
}

var _ tunnel.TailscaleCoordinator = (*TSCoordinator)(nil)
