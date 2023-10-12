package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
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
	r.Use(middleware.Recoverer)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("welcome"))
	})

	coordinator := NewTSCoordinator()
	r.Handle("/*", mux.CoordinatorHandler(coordinator))

	r.Post("/update-all", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		var res tailcfg.MapResponse

		err := json.NewDecoder(r.Body).Decode(&res)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(fmt.Sprintf(`{"error": "%s"}`, err.Error())))
			return
		}

		coordinator.nodeMutex.Lock()
		for _, node := range coordinator.nodes {
			select {
			case <-node.CloseChan:
			case node.NetMapChan <- res:
			}
		}
		coordinator.nodeMutex.Unlock()

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success": true}`))
	})

	r.Get("/nodes", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		coordinator.nodeMutex.Lock()
		defer coordinator.nodeMutex.Unlock()

		nodes := []string{}
		for k := range coordinator.nodes {
			nodes = append(nodes, k)
		}

		err := json.NewEncoder(w).Encode(nodes)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(fmt.Sprintf(`{"error": "%s"}`, err.Error())))
		}
	})

	if err := http.ListenAndServe(":3000", r); err != nil {
		panic(err)
	}
}

// -- Tailscale Coordinator --

type TSCoordinator struct {
	controlKey       key.MachinePrivate
	legacyControlKey key.MachinePrivate

	nodeMutex sync.Mutex
	nodes     map[string]TSNodeChannels
}

type TSNodeChannels struct {
	MapRequest tailcfg.MapRequest
	NetMapChan chan tailcfg.MapResponse
	ErrChan    chan error
	CloseChan  chan struct{}
}

func NewTSCoordinator() *TSCoordinator {
	controlKey, err := readOrCreatePrivateKey("tmp/control.key")
	if err != nil {
		panic(err)
	}

	legacyControlKey, err := readOrCreatePrivateKey("tmp/legacy.key")
	if err != nil {
		panic(err)
	}

	return &TSCoordinator{
		controlKey:       *controlKey,
		legacyControlKey: *legacyControlKey,
		nodeMutex:        sync.Mutex{},
		nodes:            make(map[string]TSNodeChannels),
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
	s, _ := json.MarshalIndent(req, "", "  ") //nolint:errchkjson
	log.Printf("PollNetMap - %s %s %v", peerPublicKey.String(), req.NodeKey.String(), string(s))

	resChan := make(chan tailcfg.MapResponse)
	errChan := make(chan error)

	t.nodeMutex.Lock()
	t.nodes[req.NodeKey.String()] = TSNodeChannels{
		MapRequest: req,
		NetMapChan: resChan,
		ErrChan:    errChan,
		CloseChan:  closeChannel,
	}
	t.nodeMutex.Unlock()

	go func() {
		<-closeChannel

		t.nodeMutex.Lock()
		delete(t.nodes, req.NodeKey.String())
		t.nodeMutex.Unlock()
	}()

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
	s, _ := json.MarshalIndent(req, "", "  ") //nolint:errchkjson
	log.Printf("RegisterMachine - %s %s %v", peerPublicKey.String(), req.NodeKey.String(), string(s))

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

// --- Utils ---

func readOrCreatePrivateKey(path string) (*key.MachinePrivate, error) {
	privateKey, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		machineKey := key.NewMachine()

		machineKeyStr, err := machineKey.MarshalText()
		if err != nil {
			return nil, fmt.Errorf(
				"failed to convert private key to string for saving: %w",
				err,
			)
		}
		err = os.WriteFile(path, machineKeyStr, 0o600)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to save private key to disk: %w",
				err,
			)
		}

		return &machineKey, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	trimmedPrivateKey := strings.TrimSpace(string(privateKey))

	privateKeyEnsurePrefix := trimmedPrivateKey

	if !strings.HasPrefix(trimmedPrivateKey, "privkey:") {
		privateKeyEnsurePrefix = "privkey:" + trimmedPrivateKey
	}

	var machineKey key.MachinePrivate
	if err = machineKey.UnmarshalText([]byte(privateKeyEnsurePrefix)); err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return &machineKey, nil
}
