package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/loft-sh/tunnel"
	"github.com/loft-sh/tunnel/mux"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	goipam "github.com/metal-stack/go-ipam"
)

const (
	baseDomain = "ts.loft"

	// https://tailscale.com/kb/1015/100.cidr-addresses/
	cidr = "100.64.0.0/10"
)

var (
	ipam   goipam.Ipamer
	prefix *goipam.Prefix
)

func main() {
	ctx := context.TODO()

	ipam = goipam.New(ctx)

	var err error
	prefix, err = ipam.NewPrefix(ctx, cidr)
	if err != nil {
		panic(err)
	}

	// The 100.100.100.100 is reserved for MagicDNS
	_, err = ipam.AcquireSpecificIP(ctx, prefix.Cidr, "100.100.100.100")
	if err != nil {
		panic(err)
	}

	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

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

		counter := 0

		coordinator.nodeMutex.Lock()
		for _, node := range coordinator.nodes {
			select {
			case node.NetMapChan <- res:
				counter++
			default:
			}
		}
		coordinator.nodeMutex.Unlock()

		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"success": true, "updated": %v}`, counter)
	})

	r.Get("/nodes", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		nodes := []string{}

		coordinator.nodeMutex.Lock()
		for k := range coordinator.nodes {
			nodes = append(nodes, k)
		}
		coordinator.nodeMutex.Unlock()

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
	nodes     map[string]TSNode
}

type TSNode struct {
	Ctx context.Context

	MapRequest      *tailcfg.MapRequest
	RegisterRequest *tailcfg.RegisterRequest

	UserID tailcfg.UserID
	Node   *tailcfg.Node

	NodeID tailcfg.NodeID

	NetMapChan chan tailcfg.MapResponse
	ErrChan    chan error

	IP *goipam.IP
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
		nodes:            make(map[string]TSNode),
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
func (t *TSCoordinator) PollNetMap(ctx context.Context, req tailcfg.MapRequest, peerPublicKey key.MachinePublic) (chan tailcfg.MapResponse, chan error) {
	resChan := make(chan tailcfg.MapResponse)
	errChan := make(chan error)

	t.nodeMutex.Lock()
	defer t.nodeMutex.Unlock()

	if _, ok := t.nodes[req.NodeKey.String()]; !ok {
		go func() { errChan <- fmt.Errorf("node %v not registered", req.NodeKey.String()) }()
		return resChan, errChan
	}

	node := t.nodes[req.NodeKey.String()]

	if req.Stream {
		node.Ctx = ctx
		node.MapRequest = &req
		node.NetMapChan = resChan
		node.ErrChan = errChan
	}

	var err error

	if node.IP == nil {
		node.IP, err = ipam.AcquireIP(ctx, prefix.Cidr)
		if err != nil {
			go func() { errChan <- err }()
			return resChan, errChan
		}
	}

	t.nodes[req.NodeKey.String()] = node

	// Cleanup goroutine on streaming request
	if req.Stream {
		go func() {
			<-ctx.Done()

			t.nodeMutex.Lock()
			nodeId := t.nodes[req.NodeKey.String()].NodeID
			delete(t.nodes, req.NodeKey.String())
			t.nodeMutex.Unlock()

			t.handlePeersRemoved(nodeId)

			_, _ = ipam.ReleaseIP(ctx, node.IP)
		}()
	}

	go func() {
		derpMap, err := t.DerpMap()
		if err != nil {
			errChan <- err
			return
		}

		now := time.Now()
		online := true

		dnsConfig := &tailcfg.DNSConfig{
			Proxied: true,

			Domains: []string{baseDomain},

			ExtraRecords: []tailcfg.DNSRecord{
				{
					Name:  fmt.Sprintf("aa.%s", baseDomain),
					Type:  "A",
					Value: "100.200.0.1",
				},
			},
		}

		prefix, err := node.IP.IP.Prefix(32)
		if err != nil {
			errChan <- err
			return
		}

		t.nodeMutex.Lock()
		coordinatorNodeInfo := t.nodes[req.NodeKey.String()]

		node := tailcfg.Node{
			Addresses:         []netip.Prefix{prefix},
			AllowedIPs:        []netip.Prefix{prefix},
			DiscoKey:          req.DiscoKey,
			Endpoints:         req.Endpoints,
			Hostinfo:          req.Hostinfo.View(),
			ID:                coordinatorNodeInfo.NodeID,
			Key:               req.NodeKey,
			LastSeen:          &now,
			Machine:           peerPublicKey,
			MachineAuthorized: true,
			Name:              fmt.Sprintf("%s.%s.", strings.ToLower(req.Hostinfo.Hostname), baseDomain),
			Online:            &online,
			StableID:          tailcfg.StableNodeID(fmt.Sprintf("stable-%v", coordinatorNodeInfo.NodeID)),
			User:              coordinatorNodeInfo.UserID,
		}

		if req.Hostinfo.NetInfo != nil {
			node.DERP = fmt.Sprintf("127.3.3.40:%v", req.Hostinfo.NetInfo.PreferredDERP)
		}

		coordinatorNodeInfo.Node = &node
		t.nodes[req.NodeKey.String()] = coordinatorNodeInfo

		peers := []*tailcfg.Node{}

		if !req.OmitPeers {
			for _, peer := range t.nodes {
				if peer.Node == nil {
					continue
				}

				if peer.NodeID == node.ID {
					continue
				}

				peers = append(peers, peer.Node)
			}
		}

		t.nodeMutex.Unlock()

		response := tailcfg.MapResponse{
			MapSessionHandle: req.MapSessionHandle,
			Seq:              req.MapSessionSeq + 1,
			ControlTime:      &now,

			Node:    &node,
			DERPMap: &derpMap,
			Domain:  baseDomain,

			Peers: peers,

			UserProfiles: []tailcfg.UserProfile{
				{
					ID:            node.User,
					LoginName:     "thomas.kosiewski@loft.sh",
					DisplayName:   "Thomas Kosiewski",
					ProfilePicURL: "https://lh3.google.com/u/0/ogw/AKPQZvwLeFOV6cJ_JLcLdfeiy5JFzqbSrjvwpuBs4GfZ=s64-c-mo",
				},
				{
					ID:            100,
					LoginName:     "thomas.kosiewski@loft.sh",
					DisplayName:   "Thomas Kosiewski (100)",
					ProfilePicURL: "https://lh3.google.com/u/0/ogw/AKPQZvwLeFOV6cJ_JLcLdfeiy5JFzqbSrjvwpuBs4GfZ=s64-c-mo",
				},
				{
					ID:            123,
					LoginName:     "thomas.kosiewski@loft.sh",
					DisplayName:   "Thomas Kosiewski (123)",
					ProfilePicURL: "https://lh3.google.com/u/0/ogw/AKPQZvwLeFOV6cJ_JLcLdfeiy5JFzqbSrjvwpuBs4GfZ=s64-c-mo",
				},
				{
					ID:            200,
					LoginName:     "thomas.kosiewski@loft.sh",
					DisplayName:   "Thomas Kosiewski (200)",
					ProfilePicURL: "https://lh3.google.com/u/0/ogw/AKPQZvwLeFOV6cJ_JLcLdfeiy5JFzqbSrjvwpuBs4GfZ=s64-c-mo",
				},
			},

			DNSConfig: dnsConfig,
		}

		if req.OmitPeers {
			response.Peers = nil
			response.PeersChanged = nil
			response.PeersRemoved = nil
			response.PeersChangedPatch = nil
		}

		resChan <- response

		go t.handleNewPeerChange(node)

		if !req.Stream {
			close(resChan)
			close(errChan)
		}
	}()

	return resChan, errChan
}

func (t *TSCoordinator) handleNewPeerChange(newNode tailcfg.Node) {
	t.nodeMutex.Lock()
	for _, node := range t.nodes {

		if node.Node == nil || node.Node.ID == newNode.ID {
			continue
		}

		if node.MapRequest == nil {
			continue
		}

		res := tailcfg.MapResponse{
			MapSessionHandle: node.MapRequest.MapSessionHandle,
			Seq:              node.MapRequest.MapSessionSeq + 1,

			PeersChanged:   []*tailcfg.Node{&newNode},
			PeerSeenChange: map[tailcfg.NodeID]bool{newNode.ID: true},
			OnlineChange:   map[tailcfg.NodeID]bool{newNode.ID: true},

			PacketFilter: []tailcfg.FilterRule{{
				SrcIPs: []string{"*"},
				DstPorts: []tailcfg.NetPortRange{{
					IP:    "*",
					Ports: tailcfg.PortRangeAny,
				}},
			}},
			// SSHPolicy:                 &tailcfg.SSHPolicy{},
		}

		select {
		case <-node.Ctx.Done():
		case node.NetMapChan <- res:
		}
	}
	t.nodeMutex.Unlock()
}

func (t *TSCoordinator) handlePeersRemoved(nodeID tailcfg.NodeID) {
	t.nodeMutex.Lock()
	for _, node := range t.nodes {
		if node.NodeID == nodeID {
			continue
		}

		if node.MapRequest == nil {
			continue
		}

		res := tailcfg.MapResponse{
			MapSessionHandle: node.MapRequest.MapSessionHandle,
			Seq:              node.MapRequest.MapSessionSeq + 1,

			PeersRemoved:   []tailcfg.NodeID{nodeID},
			PeerSeenChange: map[tailcfg.NodeID]bool{nodeID: false},
			OnlineChange:   map[tailcfg.NodeID]bool{nodeID: false},
			// PacketFilter:              []tailcfg.FilterRule{},
			// SSHPolicy:                 &tailcfg.SSHPolicy{},
		}

		select {
		case <-node.Ctx.Done():
		case node.NetMapChan <- res:
		}
	}
	t.nodeMutex.Unlock()
}

// RegisterMachine implements tunnel.TailscaleCoordinator.
func (t *TSCoordinator) RegisterMachine(req tailcfg.RegisterRequest, peerPublicKey key.MachinePublic) (tailcfg.RegisterResponse, error) {
	if req.Auth.AuthKey == "" {
		return tailcfg.RegisterResponse{}, errors.New("missing auth key")
	}

	userID, err := strconv.ParseInt(req.Auth.AuthKey, 10, 64)
	if err != nil {
		return tailcfg.RegisterResponse{}, fmt.Errorf("failed to parse auth key: %w", err)
	}

	// TODO: Check for  "1970-01-01T01:02:03+01:00"
	// if req.Expiry.Equal(time.UnixMicro(0)) {
	// 	t.nodeMutex.Lock()
	// 	delete(t.nodes, req.NodeKey.String())
	// 	t.nodeMutex.Unlock()

	// 	return tailcfg.RegisterResponse{}, errors.New("node has logged out")
	// }

	res := tailcfg.RegisterResponse{
		MachineAuthorized: true,
		User: tailcfg.User{
			ID:     tailcfg.UserID(userID),
			Logins: []tailcfg.LoginID{tailcfg.LoginID(userID)},
		},
		Login: tailcfg.Login{
			ID:        tailcfg.LoginID(userID),
			Provider:  req.Auth.Provider,
			LoginName: req.Auth.LoginName,
		},
	}

	t.nodeMutex.Lock()
	t.nodes[req.NodeKey.String()] = TSNode{
		UserID:          tailcfg.UserID(userID),
		RegisterRequest: &req,
		NodeID:          tailcfg.NodeID(len(t.nodes) + 1),
	}
	t.nodeMutex.Unlock()

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
