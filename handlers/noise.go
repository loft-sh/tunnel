package handlers

import (
	"errors"
	"io"
	"net/http"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"tailscale.com/control/controlhttp"
	"tailscale.com/net/netutil"
	"tailscale.com/types/key"
)

const (
	NoiseMethod  = http.MethodPost
	NoisePattern = "/ts2021"
)

type CustomNoiseHandlerRegisterer interface {
	RegisterHandler(*http.ServeMux)
}

func NoiseHandler(coordinator Coordinator, subPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := controlhttp.AcceptHTTP(r.Context(), w, r, coordinator.ControlKey(), nil)
		if err != nil {
			return
		}

		handler := CreatePeerHandler(coordinator, conn.Peer(), subPath)

		server := http.Server{}
		server.Handler = h2c.NewHandler(handler, &http2.Server{})

		if err := server.Serve(netutil.NewOneConnListener(conn, nil)); err != nil && !errors.Is(err, io.EOF) {
			handleAPIError(w, err, "Failed to accept HTTP connection")

			return
		}
	}
}

func CreatePeerHandler(coordinator Coordinator, peerPublicKey key.MachinePublic, subPath string) http.Handler {
	r := http.NewServeMux()

	r.HandleFunc(RegistrationMethod+" "+RegistrationPattern, RegistrationHandler(coordinator, peerPublicKey))
	r.HandleFunc(NetMapMethod+" "+NetMapPattern, NetMapHandler(coordinator, peerPublicKey))

	if coordinator, ok := coordinator.(DNSSetter); ok {
		r.HandleFunc(SetDNSMethod+" "+SetDNSPattern, SetDNSHandler(coordinator, peerPublicKey))
	}
	if coordinator, ok := coordinator.(HealthChanger); ok {
		r.HandleFunc(HealthChangeMethod+" "+HealthChangePattern, HealthChangeHandler(coordinator, peerPublicKey))
	}
	if coordinator, ok := coordinator.(IDTokenRequestHandler); ok {
		r.HandleFunc(IDTokenMethod+" "+IDTokenPattern, IDTokenHandler(coordinator, peerPublicKey))
	}
	if coordinator, ok := coordinator.(SSHActioner); ok {
		r.HandleFunc(SSHActionMethod+" "+SSHActionPattern, SSHActionHandler(coordinator, peerPublicKey))
	}

	if coordinator, ok := coordinator.(CustomNoiseHandlerRegisterer); ok {
		coordinator.RegisterHandler(r)
	}

	if subPath != "/" {
		return http.StripPrefix(subPath, r)
	}

	return r
}
