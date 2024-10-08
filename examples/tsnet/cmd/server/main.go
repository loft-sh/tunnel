// The tshello server demonstrates how to use Tailscale as a library.
package main

import (
	"flag"
	"fmt"
	"html"
	"log"
	"net/http"
	"strings"

	"tailscale.com/tsnet"
)

var (
	addr     = flag.String("addr", ":8080", "address to listen on")
	hostname = flag.String("hostname", "tshello", "hostname to use on the tailnet")
)

func init() {
	// envknob.Setenv("TS_DEBUG_DERP_WS_CLIENT", "true")
	// envknob.Setenv("TS_DEBUG_MAGICSOCK_PEERMAP", "true")
	// envknob.Setenv("TS_DEBUG_MAP", "true")
	// envknob.Setenv("TS_DEBUG_NETCHECK", "true")
	// envknob.Setenv("TS_DEBUG_NETLINK", "true")
	// envknob.Setenv("TS_DEBUG_NETMAP", "true")
	// envknob.Setenv("TS_DEBUG_NETSTACK", "true")
	// envknob.Setenv("TS_DEBUG_OMIT_LOCAL_ADDRS", "true")
	// envknob.Setenv("TS_DEBUG_PATCHIFY_PEER", "true")
	// envknob.Setenv("TS_DEBUG_PROFILES", "true")
	// envknob.Setenv("TS_DEBUG_REGISTER", "true")
	// envknob.Setenv("TS_DEBUG_USE_DERP_HTTP", "true")
}

func main() {
	flag.Parse()
	s := &tsnet.Server{
		AuthKey:    "100",
		ControlURL: "http://localhost:3000",
		Dir:        "./tsstate/tshello",
		Hostname:   *hostname,
	}
	defer s.Close()

	ln, err := s.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	lc, err := s.LocalClient()
	if err != nil {
		log.Fatal(err)
	}

	log.Fatal(http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, err := lc.WhoIs(r.Context(), r.RemoteAddr)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		fmt.Fprintf(w, "<html><body><h1>Hello, tailnet!</h1>\n")
		fmt.Fprintf(w, "<p>You are <b>%s</b> from <b>%s</b> (%s)</p>",
			html.EscapeString(who.UserProfile.LoginName),
			html.EscapeString(firstLabel(who.Node.ComputedName)),
			r.RemoteAddr)
	})))
}

func firstLabel(s string) string {
	s, _, _ = strings.Cut(s, ".")
	return s
}
