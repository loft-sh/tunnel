package main

import (
	"fmt"
	"log"
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

// -- Tailscale Coordinator --

type TSCoordinator struct {
	controlKey       key.MachinePrivate
	legacyControlKey key.MachinePrivate
}

func NewTSCoordinator() *TSCoordinator {
	return &TSCoordinator{
		controlKey:       key.NewMachine(),
		legacyControlKey: key.NewMachine(),
	}
}

// HealthChange implements tunnel.TailscaleCoordinator.
func (*TSCoordinator) HealthChange(req tailcfg.HealthChangeRequest) {
	panic("unimplemented")
}

// IDToken implements tunnel.TailscaleCoordinator.
func (*TSCoordinator) IDToken(req tailcfg.TokenRequest, peerPublicKey key.MachinePublic) (tailcfg.TokenResponse, error) {
	panic("unimplemented")
}

// SetDNS implements tunnel.TailscaleCoordinator.
func (*TSCoordinator) SetDNS(req tailcfg.SetDNSRequest, peerPublicKey key.MachinePublic) (tailcfg.SetDNSResponse, error) {
	panic("unimplemented")
}

// DerpMap implements tunnel.TailscaleCoordinator.
func (*TSCoordinator) DerpMap() (tailcfg.DERPMap, error) {
	return tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			900: {
				RegionID:   900,
				RegionCode: "loft",
				RegionName: "Embedded Loft DERP",
				Avoid:      false,
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "Embedded Loft DERP",
						RegionID: 900,
						HostName: "localhost",
						IPv4:     "127.0.0.1",
						DERPPort: 3340,
					},
				},
			},
		},
		OmitDefaultRegions: true,
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

// KeepAliveInterval implements tunnel.TailscaleCoordinator.
func (t *TSCoordinator) KeepAliveInterval() time.Duration {
	return 60 * time.Second
}

// PollNetMap implements tunnel.TailscaleCoordinator.
func (t *TSCoordinator) PollNetMap(req tailcfg.MapRequest, peerPublicKey key.MachinePublic, closeChannel chan struct{}) (chan tailcfg.MapResponse, chan error) {
	log.Printf("PollNetMap - req - PeerPublicKey: %+v %+v", req, peerPublicKey)

	resChan := make(chan tailcfg.MapResponse)
	errChan := make(chan error)

	go func() {
		derpMap, err := t.DerpMap()
		if err != nil {
			errChan <- err
			return
		}

		now := time.Now()
		online := true

		response := tailcfg.MapResponse{
			MapSessionHandle: req.MapSessionHandle,
			ControlTime:      &now,
			Node: &tailcfg.Node{
				Name:              fmt.Sprintf("%s.ts.loft.sh", req.Hostinfo.Hostname),
				User:              tailcfg.UserID(123),
				ID:                tailcfg.NodeID(1001),
				StableID:          tailcfg.StableNodeID("1001"),
				Online:            &online,
				LastSeen:          &now,
				MachineAuthorized: true,
			},
			DERPMap: &derpMap,
			Domain:  "ts.loft.sh",
		}

		if req.OmitPeers {
			response.Peers = nil
			response.PeersChanged = nil
			response.PeersRemoved = nil
			response.PeersChangedPatch = nil
		}

		resChan <- response
	}()

	return resChan, errChan
}

// RegisterMachine implements tunnel.TailscaleCoordinator.
func (*TSCoordinator) RegisterMachine(req tailcfg.RegisterRequest, peerPublicKey key.MachinePublic) (tailcfg.RegisterResponse, error) {
	userID := 123

	res := tailcfg.RegisterResponse{
		MachineAuthorized: true,
		User: tailcfg.User{
			ID:     tailcfg.UserID(userID),
			Logins: []tailcfg.LoginID{tailcfg.LoginID(userID)},
		},
		Login: tailcfg.Login{
			ID:          tailcfg.LoginID(userID),
			Provider:    req.Auth.Provider,
			LoginName:   req.Auth.LoginName,
			DisplayName: "MyDisplayName",
		},
	}

	return res, nil
}

var _ tunnel.TailscaleCoordinator = (*TSCoordinator)(nil)
