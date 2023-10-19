package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
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
	"github.com/invopop/jsonschema"
	"github.com/loft-sh/tunnel"
	"github.com/loft-sh/tunnel/handlers"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	goipam "github.com/metal-stack/go-ipam"
)

var (
	configFile         = flag.String("config", "", "config file to use")
	generateSchemaOnly = flag.Bool("generate-schema-only", false, "generate schema only")
)

var (
	ipam   goipam.Ipamer
	prefix *goipam.Prefix

	config Config

	derpMap           = defaultDerpMap()
	userProfiles      = defaultUserProfiles()
	extraRecords      = []tailcfg.DNSRecord{}
	keepAliveInterval = 60 * time.Second
)

var (
	ErrMissingAuthKey      = errors.New("missing auth key")
	ErrMissingUserProfiles = errors.New("missing user profiles")
)

// Config is the configuration for the coordinator.
// This is useful for running test scenarios with a pre-configured coordinator.
type Config struct {
	// HTTPListenAddr is the address that the coordinator will listen on.
	//
	// Defaults to ":3000".
	HTTPListenAddr string `json:"httpListenAddr,omitempty"`

	// ControlKey is the control key of the coordinator.
	//
	// Either this or ControlKeyLocation needs to be set.
	ControlKey *key.MachinePrivate `json:"controlKey,omitempty"`
	// ControlKeyLocation is the location of the control key on disk.
	//
	// Either this or ControlKey needs to be set.
	ControlKeyLocation string `json:"controlKeyLocation,omitempty"`
	// LegacyControlKey is the legacy control key of the coordinator.
	//
	// Either this or LegacyControlKeyLocation needs to be set.
	LegacyControlKey *key.MachinePrivate `json:"legacyControlKey,omitempty"`
	// LegacyControlKeyLocation is the location of the legacy control key on
	// disk.
	//
	// Either this or LegacyControlKey needs to be set.
	LegacyControlKeyLocation string `json:"legacyControlKeyLocation,omitempty"`
	// BaseDomain is the base domain of the coordinator. This is also known as
	// tailnet
	BaseDomain string `json:"baseDomain"`
	// CIDR is the CIDR of the tailnet.
	CIDR string `json:"cidr"`
	// KeepAliveInterval is the keep alive interval of the coordinator.
	//
	// This is the interval in which the coordinator will send keep alive
	// messages to the nodes. It will also be reused as the interval for the
	// cleanup goroutine that removes nodes that have disconnected.
	//
	// Defaults to 60 seconds.
	KeepAliveInterval time.Duration `json:"keepAliveInterval,omitempty"`
	// DerpMap is the DERP map that the coordinator will include in the
	// MapResponse.
	DerpMap *tailcfg.DERPMap `json:"derpMap,omitempty"`
	// ExtraRecords is a list of extra DNS records that the coordinator will
	// include in the MapResponse.
	ExtraRecords *[]tailcfg.DNSRecord `json:"extraRecords,omitempty"`
	// UserProfiles is a list of user profiles that the coordinator will
	// include in the MapResponse.
	UserProfiles *[]tailcfg.UserProfile `json:"userProfiles"`

	// Nodes is a list of nodes that the coordinator will pre-populate in its
	// internal node list.
	//
	// Nodes that are included here will not be required to perform
	// authentication with the coordinator.
	Nodes *[]struct {
		// NodeKey is the node key of the node.
		NodeKey string `json:"nodeKey"`
		// PeerPublicKey is the peer public key of the node.
		PeerPublicKey string `json:"peerPublicKey"`
		// UserID is the user id of the node.
		UserID tailcfg.UserID `json:"userId"`
		// NodeID is the node id of the node.
		NodeID tailcfg.NodeID `json:"nodeId"`
		// IP is the IP of the node.
		IP string `json:"ip,omitempty"`
	} `json:"nodes,omitempty"`
}

func main() {
	flag.Parse()

	if *generateSchemaOnly {
		generateSchema()
		return
	}

	if err := loadGlobalConfig(); err != nil {
		panic(err)
	}

	ctx := context.TODO()

	ipam = goipam.New(ctx)

	var err error
	prefix, err = ipam.NewPrefix(ctx, config.CIDR)
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
	r.Handle("/*", handlers.CoordinatorHandler(coordinator))

	r.Get("/nodes", NodeInfoHandler(coordinator))

	addr := ":3000"

	if config.HTTPListenAddr != "" {
		addr = config.HTTPListenAddr
	}

	if err := http.ListenAndServe(addr, r); err != nil {
		panic(err)
	}
}

// NodeInfoHandler returns a list of all nodes that are connected to the
// coordinator.
func NodeInfoHandler(coordinator *TSCoordinator) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		type nodeInfo struct {
			NodeID     tailcfg.NodeID `json:"nodeId"`
			UserID     tailcfg.UserID `json:"userId"`
			MachineKey string         `json:"machineKey"`
			NodeKey    string         `json:"nodeKey"`
		}

		nodes := []nodeInfo{}

		coordinator.nodeMutex.Lock()
		for k, v := range coordinator.nodes {
			nodes = append(nodes, nodeInfo{
				NodeID:     v.NodeID,
				UserID:     v.UserID,
				NodeKey:    v.NodePublicKey.String(),
				MachineKey: k.String(),
			})
		}
		coordinator.nodeMutex.Unlock()

		err := json.NewEncoder(w).Encode(nodes)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(fmt.Sprintf(`{"error": "%s"}`, err.Error())))
		}
	}
}

// -- Tailscale Coordinator --

// TSNode is a node that is connected to the coordinator.
// It contains all the information that is needed to stream a MapResponse to the
// node.
type TSNode struct {
	// Done is the context done channel for the streaming request. This channel
	// is closed when the request is canceled.
	Done <-chan struct{}

	// NodePublicKey is the node public key of the node. This is used as a
	// "sessions" key for the node.
	NodePublicKey key.NodePublic

	// MapRequest is the map request of the node.
	MapRequest *tailcfg.MapRequest

	// UserID is the user id of the node.
	UserID tailcfg.UserID
	// NodeID is the node id of the node.
	NodeID tailcfg.NodeID
	// Node is the node of the node.
	Node *tailcfg.Node

	// NetMapChan is channel that streams MapResponse to the node. Closing this
	// channel will cause the connection to be closed.
	NetMapChan chan tailcfg.MapResponse
	// ErrChan is the error response channel for the node. It will forward an
	// API error message to the peer and close the connection
	ErrChan chan error

	// IP is the IP of the node.
	IP *goipam.IP

	// RemovalTimer is the timer that will remove the node from the coordinator.
	// This is used to cleanup nodes that have disconnected, if they have not
	// reconnected within the keep alive interval.
	RemovalTimer *time.Timer
}

// TSCoordinator is a Tailscale coordinator.
type TSCoordinator struct {
	nodeMutex sync.Mutex
	nodes     map[key.MachinePublic]TSNode
}

// NewTSCoordinator creates a new Tailscale coordinator.
func NewTSCoordinator() *TSCoordinator {
	coordinator := &TSCoordinator{
		nodes: map[key.MachinePublic]TSNode{},
	}

	if config.Nodes == nil {
		return coordinator
	}

	for _, node := range *config.Nodes {
		nodeKey := key.NodePublic{}
		err := nodeKey.UnmarshalText([]byte(node.NodeKey))
		if err != nil {
			panic(err)
		}

		peerPublicKey := key.MachinePublic{}
		err = peerPublicKey.UnmarshalText([]byte(node.PeerPublicKey))
		if err != nil {
			panic(err)
		}

		var ip *goipam.IP

		if node.IP != "" {
			ip, err = ipam.AcquireSpecificIP(context.TODO(), prefix.Cidr, node.IP)
			if err != nil {
				panic(err)
			}
		}

		coordinator.nodes[peerPublicKey] = TSNode{
			UserID:        node.UserID,
			NodeID:        node.NodeID,
			NodePublicKey: nodeKey,
			IP:            ip,
		}
	}

	return coordinator
}

// SSHAction implements tunnel.TailscaleCoordinator.
func (*TSCoordinator) SSHAction(r *http.Request, peerPublicKey key.MachinePublic) (tailcfg.SSHAction, error) {
	panic("unimplemented")
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
	return derpMap, nil
}

// ControlKey implements tunnel.TailscaleCoordinator.
func (t *TSCoordinator) ControlKey() key.MachinePrivate {
	return *config.ControlKey
}

// LegacyControlKey implements tunnel.TailscaleCoordinator.
func (t *TSCoordinator) LegacyControlKey() key.MachinePrivate {
	return *config.LegacyControlKey
}

// KeepAliveInterval implements tunnel.TailscaleCoordinator.
func (t *TSCoordinator) KeepAliveInterval() time.Duration {
	return keepAliveInterval
}

// PollNetMap implements tunnel.TailscaleCoordinator.
func (t *TSCoordinator) PollNetMap(ctx context.Context, req tailcfg.MapRequest, peerPublicKey key.MachinePublic) (chan tailcfg.MapResponse, chan error) {
	resChan := make(chan tailcfg.MapResponse)
	errChan := make(chan error)

	t.nodeMutex.Lock()
	defer t.nodeMutex.Unlock()

	if _, ok := t.nodes[peerPublicKey]; !ok {
		//nolint:goerr113
		go func() { errChan <- fmt.Errorf("node %v not registered", peerPublicKey) }()
		return resChan, errChan
	}

	node := t.nodes[peerPublicKey]

	if node.RemovalTimer != nil {
		node.RemovalTimer.Stop()
		node.RemovalTimer = nil
	}

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

	t.nodes[peerPublicKey] = node

	// Cleanup goroutine on streaming request
	if req.Stream {
		go t.cleanupDisconnectedNode(ctx, peerPublicKey, node)
	}

	go t.handleNetMapRequest(resChan, errChan, req, peerPublicKey, node.IP)

	return resChan, errChan
}

// DNSConfig implements tunnel.TailscaleCoordinator.
func (t *TSCoordinator) DNSConfig() *tailcfg.DNSConfig {
	return &tailcfg.DNSConfig{
		Proxied:      true,
		Domains:      []string{config.BaseDomain},
		ExtraRecords: extraRecords,
	}
}

// handleNetMapRequest handles a netmap request.
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

	coordinatorNodeInfo := t.nodes[peerPublicKey]
	node := t.getNode(req, coordinatorNodeInfo, peerPublicKey, prefix, &now, &online)
	coordinatorNodeInfo.Node = &node
	t.nodes[peerPublicKey] = coordinatorNodeInfo

	peers := t.peersForNode(req, node)

	t.nodeMutex.Unlock()

	userProfiles := userProfiles

	response := tailcfg.MapResponse{
		MapSessionHandle: req.MapSessionHandle,
		Seq:              req.MapSessionSeq + 1,
		ControlTime:      &now,
		Node:             &node,
		DERPMap:          &derpMap,
		Domain:           config.BaseDomain,
		Peers:            peers,
		UserProfiles:     userProfiles,
		DNSConfig:        dnsConfig,
	}

	resChan <- response

	//nolint:godox
	// TODO(ThomasK33): This needs to get debounced, as clients might send
	// updates in a very quick succession, which would result in a lot of
	// unnecessary updates/noise.
	t.announcePeerChange(node)

	if !req.Stream {
		close(resChan)
		close(errChan)
	}
}

// peersForNode returns a list of peers for a given node.
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

// getNode returns a node for a given request.
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
		Name:              fmt.Sprintf("%s.%s.", strings.ToLower(req.Hostinfo.Hostname), config.BaseDomain),
		Online:            online,
		StableID:          tailcfg.StableNodeID(fmt.Sprintf("stable-%v", coordinatorNodeInfo.NodeID)),
		User:              coordinatorNodeInfo.UserID,
	}

	if req.Hostinfo.NetInfo != nil {
		node.DERP = fmt.Sprintf("127.3.3.40:%v", req.Hostinfo.NetInfo.PreferredDERP)
	}
	return node
}

// cleanupDisconnectedNode cleans up a node that has disconnected from the
// coordinator.
func (t *TSCoordinator) cleanupDisconnectedNode(ctx context.Context, peerPublicKey key.MachinePublic, node TSNode) {
	<-ctx.Done()

	online := false
	now := time.Now()

	if node.Node != nil {
		node.Node.Online = &online
		node.Node.LastSeen = &now
	}

	if node.RemovalTimer != nil {
		node.RemovalTimer.Stop()
	}
	node.RemovalTimer = time.AfterFunc(keepAliveInterval, func() {
		if node.IP != nil {
			_, _ = ipam.ReleaseIP(context.Background(), node.IP)
		}

		t.nodeMutex.Lock()
		delete(t.nodes, peerPublicKey)
		t.nodeMutex.Unlock()

		t.announcePeerDisconnected(node.NodeID, true)
	})

	t.announcePeerDisconnected(node.NodeID, false)
}

// announcePeerChange announces a peer change to all nodes that are connected to
// the coordinator.
func (t *TSCoordinator) announcePeerChange(newNode tailcfg.Node) {
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

// announcePeerDisconnected announces a peer disconnect to all nodes that are
// connected to the coordinator. If `remove` is set to true, the node will be
// removed from each node's peer list.
func (t *TSCoordinator) announcePeerDisconnected(nodeID tailcfg.NodeID, remove bool) {
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

			PeerSeenChange: map[tailcfg.NodeID]bool{nodeID: false},
			OnlineChange:   map[tailcfg.NodeID]bool{nodeID: false},
		}

		if remove {
			res.PeersRemoved = []tailcfg.NodeID{nodeID}
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
	// If we already have a node configured with the nodeKey and peerPublicKey,
	// we should return the same nodeID and userID as before and omit any kind
	// of authentication, as this was already done before.
	t.nodeMutex.Lock()
	node, ok := t.nodes[peerPublicKey]
	t.nodeMutex.Unlock()

	var userID int64

	if ok {
		userID = int64(node.UserID)
	} else {
		var err error
		node, err = t.authenticateMachine(req, peerPublicKey)
		if err != nil {
			return tailcfg.RegisterResponse{}, fmt.Errorf("failed to authenticate machine: %w", err)
		}
		userID = int64(node.UserID)
	}

	// Check for "1970-01-01T01:02:03+01:00" (123 seconds since unix zero
	// timestamp) as that means that a node has purposefully logged out.
	if req.Expiry.Unix() == 123 {
		t.nodeMutex.Lock()
		if node.IP != nil {
			_, _ = ipam.ReleaseIP(context.TODO(), node.IP)
		}
		delete(t.nodes, peerPublicKey)
		t.nodeMutex.Unlock()
		t.announcePeerDisconnected(node.NodeID, true)

		return tailcfg.RegisterResponse{}, nil
	}

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

	return res, nil
}

// authenticateMachine authenticates a machine and returns the node that is
// associated with the machine.
func (t *TSCoordinator) authenticateMachine(req tailcfg.RegisterRequest, peerPublicKey key.MachinePublic) (TSNode, error) {
	if req.Auth.AuthKey == "" {
		return TSNode{}, ErrMissingAuthKey
	}

	userID, err := strconv.ParseInt(req.Auth.AuthKey, 10, 64)
	if err != nil {
		return TSNode{}, fmt.Errorf("failed to parse auth key: %w", err)
	}

	profileFound := false

	for _, profile := range userProfiles {
		if profile.ID == tailcfg.UserID(userID) {
			profileFound = true
			break
		}
	}

	if !profileFound {
		//nolint:goerr113
		return TSNode{}, fmt.Errorf("user profile with id %v not found", userID)
	}

	t.nodeMutex.Lock()
	node := TSNode{
		UserID:        tailcfg.UserID(userID),
		NodeID:        tailcfg.NodeID(len(t.nodes) + 1),
		NodePublicKey: req.NodeKey,
	}
	t.nodes[peerPublicKey] = node
	t.nodeMutex.Unlock()

	return node, nil
}

// TSCoordinator implements tunnel.TailscaleCoordinator.
var _ tunnel.TailscaleCoordinator = (*TSCoordinator)(nil)

// --- Utils ---

//nolint:cyclop
func loadGlobalConfig() error {
	if configFile != nil && *configFile != "" {
		content, err := os.ReadFile(*configFile)
		if err != nil {
			return fmt.Errorf("failed to read config file: %w", err)
		}

		err = json.Unmarshal(content, &config)
		if err != nil {
			return fmt.Errorf("failed to parse config file: %w", err)
		}
	}

	if err := readKeysIfNecessary(); err != nil {
		return fmt.Errorf("failed to read keys: %w", err)
	}

	if config.BaseDomain == "" {
		config.BaseDomain = "ts.loft"
	}

	if config.CIDR == "" {
		// https://tailscale.com/kb/1015/100.cidr-addresses/
		config.CIDR = "100.64.0.0/10"
	}

	if config.DerpMap != nil {
		derpMap = *config.DerpMap
	}

	if config.KeepAliveInterval != 0 {
		keepAliveInterval = config.KeepAliveInterval
	}

	if config.UserProfiles != nil {
		userProfiles = *config.UserProfiles
	}

	if config.ExtraRecords != nil {
		extraRecords = *config.ExtraRecords
	}

	return nil
}

// readKeysIfNecessary reads the control key and legacy control key from disk,
// if they are not already set.
func readKeysIfNecessary() error {
	if config.ControlKey == nil {
		if config.ControlKeyLocation == "" {
			config.ControlKeyLocation = "/tmp/control.key"
		}

		controlKey, err := readOrCreatePrivateKey(config.ControlKeyLocation)
		if err != nil {
			return fmt.Errorf("failed to read control key: %w", err)
		}
		config.ControlKey = controlKey
	}

	if config.LegacyControlKey == nil {
		if config.LegacyControlKeyLocation == "" {
			config.LegacyControlKeyLocation = "/tmp/legacy-control.key"
		}

		legacyControlKey, err := readOrCreatePrivateKey(config.LegacyControlKeyLocation)
		if err != nil {
			return fmt.Errorf("failed to read legacy control key: %w", err)
		}
		config.LegacyControlKey = legacyControlKey
	}

	return nil
}

// defaultDerpMap returns a default DERP map that is used if no DERP map is
// configured.
func defaultDerpMap() tailcfg.DERPMap {
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
	}
}

// defaultUserProfiles returns a default list of user profiles that is used if
// no user profiles are configured.
func defaultUserProfiles() []tailcfg.UserProfile {
	return []tailcfg.UserProfile{
		{
			ID:            100,
			LoginName:     "test",
			DisplayName:   "Test User",
			ProfilePicURL: "https://avatars.githubusercontent.com/u/0?v=4",
			Groups:        []string{"admins"},
		},
	}
}

// readOrCreatePrivateKey reads a private key from disk or creates a new one if
// it does not exist.
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

// generateSchema generates the JSON schema for the config struct.
func generateSchema() {
	schema := jsonschema.Reflect(&Config{})
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(schema); err != nil {
		panic(err)
	}
}
