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

	ErrMissingAuthKey = errors.New("missing auth key")
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

type TSNode struct {
	Done <-chan struct{}

	MapRequest      *tailcfg.MapRequest
	RegisterRequest *tailcfg.RegisterRequest

	UserID tailcfg.UserID
	Node   *tailcfg.Node

	NodeID tailcfg.NodeID

	NetMapChan chan tailcfg.MapResponse
	ErrChan    chan error

	IP *goipam.IP
}

type TSCoordinator struct {
	controlKey       key.MachinePrivate
	legacyControlKey key.MachinePrivate

	nodeMutex sync.Mutex
	nodes     map[string]TSNode
}

// SSHAction implements tunnel.TailscaleCoordinator.
func (*TSCoordinator) SSHAction(r *http.Request, peerPublicKey key.MachinePublic) (tailcfg.SSHAction, error) {
	panic("unimplemented")
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
		//nolint:goerr113
		go func() { errChan <- fmt.Errorf("node %v not registered", req.NodeKey.String()) }()
		return resChan, errChan
	}

	node := t.nodes[req.NodeKey.String()]

	if req.Stream {
		node.Done = ctx.Done()
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
		go cleanup(ctx, t, req, node)
	}

	go t.handleNetMapRequest(resChan, errChan, req, peerPublicKey, node.IP)

	return resChan, errChan
}

func (t *TSCoordinator) DNSConfig() *tailcfg.DNSConfig {
	return &tailcfg.DNSConfig{
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
}

func (t *TSCoordinator) handleNetMapRequest(resChan chan tailcfg.MapResponse, errChan chan error, req tailcfg.MapRequest, peerPublicKey key.MachinePublic, ip *goipam.IP) {
	derpMap, err := t.DerpMap()
	if err != nil {
		errChan <- err
		return
	}

	now := time.Now()
	online := true

	dnsConfig := t.DNSConfig()

	prefix, err := ip.IP.Prefix(32)
	if err != nil {
		errChan <- err
		return
	}

	t.nodeMutex.Lock()

	coordinatorNodeInfo := t.nodes[req.NodeKey.String()]
	node := t.getNode(req, coordinatorNodeInfo, peerPublicKey, prefix, &now, &online)
	coordinatorNodeInfo.Node = &node
	t.nodes[req.NodeKey.String()] = coordinatorNodeInfo

	peers := t.peersForNode(req, node)

	t.nodeMutex.Unlock()

	userProfiles := t.userProfiles(node)

	response := tailcfg.MapResponse{
		MapSessionHandle: req.MapSessionHandle,
		Seq:              req.MapSessionSeq + 1,
		ControlTime:      &now,
		Node:             &node,
		DERPMap:          &derpMap,
		Domain:           baseDomain,
		Peers:            peers,
		UserProfiles:     userProfiles,
		DNSConfig:        dnsConfig,
	}

	if req.OmitPeers {
		response.Peers = nil
		response.PeersChanged = nil
		response.PeersRemoved = nil
		response.PeersChangedPatch = nil
	}

	resChan <- response

	// TODO(ThomasK33): This needs to get debounced, as clients might send
	// updates in a very quick succession, which would result in a lot of
	// unnecessary updates.
	t.handleNewPeerChange(node)

	if !req.Stream {
		close(resChan)
		close(errChan)
	}
}

func (*TSCoordinator) userProfiles(node tailcfg.Node) []tailcfg.UserProfile {
	userProfiles := []tailcfg.UserProfile{
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
	}
	return userProfiles
}

func (t *TSCoordinator) peersForNode(req tailcfg.MapRequest, node tailcfg.Node) []*tailcfg.Node {
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

	return peers
}

func (*TSCoordinator) getNode(req tailcfg.MapRequest, coordinatorNodeInfo TSNode, peerPublicKey key.MachinePublic, addresses netip.Prefix, lastSeen *time.Time, online *bool) tailcfg.Node {
	node := tailcfg.Node{
		Addresses:         []netip.Prefix{addresses},
		AllowedIPs:        []netip.Prefix{addresses},
		DiscoKey:          req.DiscoKey,
		Endpoints:         req.Endpoints,
		Hostinfo:          req.Hostinfo.View(),
		ID:                coordinatorNodeInfo.NodeID,
		Key:               req.NodeKey,
		LastSeen:          lastSeen,
		Machine:           peerPublicKey,
		MachineAuthorized: true,
		Name:              fmt.Sprintf("%s.%s.", strings.ToLower(req.Hostinfo.Hostname), baseDomain),
		Online:            online,
		StableID:          tailcfg.StableNodeID(fmt.Sprintf("stable-%v", coordinatorNodeInfo.NodeID)),
		User:              coordinatorNodeInfo.UserID,
	}

	if req.Hostinfo.NetInfo != nil {
		node.DERP = fmt.Sprintf("127.3.3.40:%v", req.Hostinfo.NetInfo.PreferredDERP)
	}
	return node
}

func cleanup(ctx context.Context, t *TSCoordinator, req tailcfg.MapRequest, node TSNode) {
	<-ctx.Done()

	t.nodeMutex.Lock()
	nodeID := t.nodes[req.NodeKey.String()].NodeID
	delete(t.nodes, req.NodeKey.String())
	t.nodeMutex.Unlock()

	t.handlePeersRemoved(nodeID)

	_, _ = ipam.ReleaseIP(ctx, node.IP)
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
		}

		select {
		case <-node.Done:
		case node.NetMapChan <- res:
		default:
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
		}

		select {
		case <-node.Done:
		case node.NetMapChan <- res:
		default:
		}
	}
	t.nodeMutex.Unlock()
}

// RegisterMachine implements tunnel.TailscaleCoordinator.
func (t *TSCoordinator) RegisterMachine(req tailcfg.RegisterRequest, peerPublicKey key.MachinePublic) (tailcfg.RegisterResponse, error) {
	if req.Auth.AuthKey == "" {
		return tailcfg.RegisterResponse{}, ErrMissingAuthKey
	}

	userID, err := strconv.ParseInt(req.Auth.AuthKey, 10, 64)
	if err != nil {
		return tailcfg.RegisterResponse{}, fmt.Errorf("failed to parse auth key: %w", err)
	}

	// TODO(ThomasK33): Check for "1970-01-01T01:02:03+01:00" as that means that
	// a node has purposefully logged out

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
