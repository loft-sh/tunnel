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
	"os/signal"
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
	// ControlKey is the control key of the coordinator.
	//
	// Either this or ControlKeyLocation needs to be set.
	ControlKey *key.MachinePrivate `json:"controlKey,omitempty"`
	// LegacyControlKey is the legacy control key of the coordinator.
	//
	// Either this or LegacyControlKeyLocation needs to be set.
	LegacyControlKey *key.MachinePrivate `json:"legacyControlKey,omitempty"`
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
		// Name is the FQDN of the node. It is also the MagicDNS name for the
		// node. It has a trailing dot. e.g. "host.tail-scale.ts.net."
		Name string `json:"name"`
		// NodeKey is the node key of the node.
		NodeKey string `json:"nodeKey,omitempty"`
		// MachineKey is the peer public key of the node.
		MachineKey string `json:"machineKey"`
		// IP is the IP of the node.
		IP string `json:"ip,omitempty"`
		// UserID is the user id of the node.
		UserID tailcfg.UserID `json:"userId"`
		// NodeID is the node id of the node.
		NodeID tailcfg.NodeID `json:"nodeId"`
	} `json:"nodes,omitempty"`

	// HTTPListenAddr is the address that the coordinator will listen on.
	//
	// Defaults to ":3000".
	HTTPListenAddr string `json:"httpListenAddr,omitempty"`

	// ControlKeyLocation is the location of the control key on disk.
	//
	// Either this or ControlKey needs to be set.
	ControlKeyLocation string `json:"controlKeyLocation,omitempty"`
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer stop()

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

	coordinator := NewCoordinator(ctx)
	r.Mount("/", handlers.CoordinatorHandler(coordinator))

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
func NodeInfoHandler(coordinator *Coordinator) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		type nodeInfo struct {
			MachineKey string         `json:"machineKey"`
			NodeKey    string         `json:"nodeKey"`
			Name       string         `json:"name"`
			NodeID     tailcfg.NodeID `json:"nodeId"`
			UserID     tailcfg.UserID `json:"userId"`
		}

		nodes := []nodeInfo{}

		coordinator.nodeMutex.Lock()
		for k, v := range coordinator.nodes {
			nodes = append(nodes, nodeInfo{
				NodeID:     v.Node.ID,
				UserID:     v.Node.User,
				NodeKey:    v.Node.Key.String(),
				MachineKey: k.String(),
				Name:       v.Node.Name,
			})
		}
		coordinator.nodeMutex.Unlock()

		err := json.NewEncoder(w).Encode(nodes)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprintf(w, `{"error": "%s"}`, err.Error())
		}
	}
}

// -- Coordinator --

// Node is a node that is connected to the coordinator.
// It contains all the information that is needed to stream a MapResponse to the
// node.
type Node struct {
	// Done is the context done channel for the streaming request. This channel
	// is closed when the request is canceled.
	Done <-chan struct{}
	// NetMapChan is channel that streams MapResponse to the node. Closing this
	// channel will cause the connection to be closed.
	NetMapChan chan tailcfg.MapResponse
	// ErrChan is the error response channel for the node. It will forward an
	// API error message to the peer and close the connection
	ErrChan chan error

	// RemovalTimer is the timer that will remove the node from the coordinator.
	// This is used to cleanup nodes that have disconnected, if they have not
	// reconnected within the keep alive interval.
	RemovalTimer *time.Timer
	// Node is the node of the node.
	Node tailcfg.Node

	// MapRequest is the map request of the node.
	MapRequest tailcfg.MapRequest
}

// TSCoordinator implements tunnel.BareCoordinator.
var _ tunnel.BareCoordinator = (*Coordinator)(nil)

// Coordinator is a coordinator.
type Coordinator struct {
	nodes     map[key.MachinePublic]Node
	nodeMutex sync.Mutex
}

// NewCoordinator creates a new coordinator.
func NewCoordinator(ctx context.Context) *Coordinator {
	coordinator := &Coordinator{
		nodes: map[key.MachinePublic]Node{},
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
		err = peerPublicKey.UnmarshalText([]byte(node.MachineKey))
		if err != nil {
			panic(err)
		}

		var ip *goipam.IP

		if node.IP != "" {
			ip, err = ipam.AcquireSpecificIP(ctx, prefix.Cidr, node.IP)
			if err != nil {
				panic(err)
			}
		}

		prefix, err := ip.IP.Prefix(32)
		if err != nil {
			panic(err)
		}

		coordinator.nodes[peerPublicKey] = Node{
			Node: tailcfg.Node{
				ID:         node.NodeID,
				User:       node.UserID,
				Key:        nodeKey,
				Name:       node.Name,
				Addresses:  []netip.Prefix{prefix},
				AllowedIPs: []netip.Prefix{prefix},
			},
		}
	}

	return coordinator
}

// DerpMap implements tunnel.Coordinator.
func (*Coordinator) DerpMap(ctx context.Context) (tailcfg.DERPMap, error) {
	return derpMap, nil
}

// ControlKey implements tunnel.Coordinator.
func (t *Coordinator) ControlKey() key.MachinePrivate {
	return *config.ControlKey
}

// LegacyControlKey implements tunnel.Coordinator.
func (t *Coordinator) LegacyControlKey() key.MachinePrivate {
	return *config.LegacyControlKey
}

// KeepAliveInterval implements tunnel.Coordinator.
func (t *Coordinator) KeepAliveInterval() time.Duration {
	return keepAliveInterval
}

// NetMap implements tunnel.Coordinator.
func (t *Coordinator) NetMap(ctx context.Context, req tailcfg.MapRequest, peerPublicKey key.MachinePublic) (chan tailcfg.MapResponse, chan error) {
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
		node.MapRequest = req
		node.NetMapChan = resChan
		node.ErrChan = errChan
	}

	if len(node.Node.Addresses) == 0 {
		ip, err := ipam.AcquireIP(ctx, prefix.Cidr)
		if err != nil {
			go func() { errChan <- err }()
			return resChan, errChan
		}

		prefix, err := ip.IP.Prefix(32)
		if err != nil {
			go func() { errChan <- err }()
			return resChan, errChan
		}

		node.Node.Addresses = []netip.Prefix{prefix}
		node.Node.AllowedIPs = []netip.Prefix{prefix}
	}

	t.nodes[peerPublicKey] = node

	// Cleanup goroutine on streaming request
	if req.Stream {
		go t.cleanupDisconnectedNode(ctx, peerPublicKey, node)
	}

	go t.handleNetMapRequest(ctx, resChan, errChan, req, peerPublicKey, &node.Node)

	return resChan, errChan
}

// DNSConfig implements tunnel.Coordinator.
func (t *Coordinator) DNSConfig() *tailcfg.DNSConfig {
	return &tailcfg.DNSConfig{
		Proxied:      true,
		Domains:      []string{config.BaseDomain},
		ExtraRecords: extraRecords,
	}
}

// handleNetMapRequest handles a netmap request.
func (t *Coordinator) handleNetMapRequest(ctx context.Context, resChan chan tailcfg.MapResponse, errChan chan error, req tailcfg.MapRequest, peerPublicKey key.MachinePublic, node *tailcfg.Node) {
	derpMap, err := t.DerpMap(ctx)
	if err != nil {
		errChan <- err
		return
	}

	now := time.Now()
	online := true
	dnsConfig := t.DNSConfig()

	node.DiscoKey = req.DiscoKey
	node.Endpoints = req.Endpoints
	node.Hostinfo = req.Hostinfo.View()
	node.Key = req.NodeKey
	node.LastSeen = &now
	node.Machine = peerPublicKey
	node.MachineAuthorized = true
	node.Name = fmt.Sprintf("%s.%s.", strings.ToLower(req.Hostinfo.Hostname), config.BaseDomain)
	node.Online = &online
	node.StableID = tailcfg.StableNodeID(fmt.Sprintf("stable-%v", node.ID))

	if req.Hostinfo.NetInfo != nil {
		node.DERP = fmt.Sprintf("127.3.3.40:%v", req.Hostinfo.NetInfo.PreferredDERP)
	}

	peers := t.peersForNode(req, *node)

	userProfiles := userProfiles

	response := tailcfg.MapResponse{
		MapSessionHandle: req.MapSessionHandle,
		Seq:              req.MapSessionSeq + 1,
		ControlTime:      &now,
		Node:             node,
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
	t.announcePeerChange(*node)

	if !req.Stream {
		close(resChan)
		close(errChan)
	}
}

// peersForNode returns a list of peers for a given node.
func (t *Coordinator) peersForNode(req tailcfg.MapRequest, node tailcfg.Node) []*tailcfg.Node {
	peers := []*tailcfg.Node{}

	if !req.OmitPeers {
		for _, peer := range t.nodes {
			if peer.Node.ID == node.ID {
				continue
			}

			node := peer.Node
			peers = append(peers, &node)
		}
	}

	return peers
}

// cleanupDisconnectedNode cleans up a node that has disconnected from the
// coordinator.
func (t *Coordinator) cleanupDisconnectedNode(ctx context.Context, peerPublicKey key.MachinePublic, node Node) {
	<-ctx.Done()

	online := false
	now := time.Now()

	node.Node.Online = &online
	node.Node.LastSeen = &now

	if node.RemovalTimer != nil {
		node.RemovalTimer.Stop()
	}
	node.RemovalTimer = time.AfterFunc(keepAliveInterval, func() {
		if len(node.Node.Addresses) != 0 {
			for _, address := range node.Node.Addresses {
				_ = ipam.ReleaseIPFromPrefix(ctx, prefix.Cidr, address.Addr().String())
			}
		}

		t.nodeMutex.Lock()
		delete(t.nodes, peerPublicKey)
		t.nodeMutex.Unlock()

		t.announcePeerDisconnected(node.Node.ID, true)
	})

	t.announcePeerDisconnected(node.Node.ID, false)
}

// announcePeerChange announces a peer change to all nodes that are connected to
// the coordinator.
func (t *Coordinator) announcePeerChange(newNode tailcfg.Node) {
	t.nodeMutex.Lock()
	for _, node := range t.nodes {
		if node.Node.ID == newNode.ID {
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
func (t *Coordinator) announcePeerDisconnected(nodeID tailcfg.NodeID, remove bool) {
	t.nodeMutex.Lock()
	for _, node := range t.nodes {
		if node.Node.ID == nodeID {
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

// RegisterMachine implements tunnel.Coordinator.
func (t *Coordinator) RegisterMachine(ctx context.Context, req tailcfg.RegisterRequest, peerPublicKey key.MachinePublic) (tailcfg.RegisterResponse, error) {
	// If we already have a node configured with the nodeKey and peerPublicKey,
	// we should return the same nodeID and userID as before and omit any kind
	// of authentication, as this was already done before.
	t.nodeMutex.Lock()
	node, ok := t.nodes[peerPublicKey]
	t.nodeMutex.Unlock()

	var userID int64

	if ok {
		userID = int64(node.Node.User)
	} else {
		var err error
		node, err = t.authenticateMachine(req, peerPublicKey)
		if err != nil {
			return tailcfg.RegisterResponse{}, fmt.Errorf("failed to authenticate machine: %w", err)
		}
		userID = int64(node.Node.User)
	}

	// Check for "1970-01-01T01:02:03+01:00" (123 seconds since unix zero
	// timestamp) as that means that a node has purposefully logged out.
	if req.Expiry.Unix() == 123 {
		if len(node.Node.Addresses) != 0 {
			for _, address := range node.Node.Addresses {
				_ = ipam.ReleaseIPFromPrefix(ctx, prefix.Cidr, address.Addr().String())
			}
		}
		t.nodeMutex.Lock()
		delete(t.nodes, peerPublicKey)
		t.nodeMutex.Unlock()
		t.announcePeerDisconnected(node.Node.ID, true)

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
			Provider:  "unknown",
			LoginName: fmt.Sprintf("userid-%v", userID),
		},
	}

	return res, nil
}

// authenticateMachine authenticates a machine and returns the node that is
// associated with the machine.
func (t *Coordinator) authenticateMachine(req tailcfg.RegisterRequest, peerPublicKey key.MachinePublic) (Node, error) {
	if req.Auth.AuthKey == "" {
		return Node{}, ErrMissingAuthKey
	}

	userID, err := strconv.ParseInt(req.Auth.AuthKey, 10, 64)
	if err != nil {
		return Node{}, fmt.Errorf("failed to parse auth key: %w", err)
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
		return Node{}, fmt.Errorf("user profile with id %v not found", userID)
	}

	t.nodeMutex.Lock()
	node := Node{
		Node: tailcfg.Node{
			ID:   tailcfg.NodeID(len(t.nodes) + 1),
			User: tailcfg.UserID(userID),
			Key:  req.NodeKey,
		},
	}
	t.nodes[peerPublicKey] = node
	t.nodeMutex.Unlock()

	return node, nil
}

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
						Name:      "Embedded Loft DERP (A)",
						RegionID:  900,
						HostName:  "derp-a",
						IPv4:      "127.0.0.1",
						DERPPort:  443,
						CanPort80: true,
					},
					{
						Name:      "Embedded Loft DERP (B)",
						RegionID:  900,
						HostName:  "derp-b",
						IPv4:      "127.0.0.1",
						DERPPort:  8443,
						CanPort80: false,
					},
					{
						Name:      "Embedded Loft DERP (C)",
						RegionID:  900,
						HostName:  "derp-c",
						IPv4:      "127.0.0.1",
						DERPPort:  9443,
						CanPort80: false,
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
