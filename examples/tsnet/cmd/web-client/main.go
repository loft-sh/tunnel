// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The web-client command demonstrates serving the Tailscale web client over tsnet.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"tailscale.com/client/web"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
)

var (
	addr    = flag.String("addr", "localhost:8060", "address of Tailscale web client")
	devMode = flag.Bool("dev", false, "run web client in dev mode")
)

func init() {
	// envknob.Setenv("TS_DEBUG_USE_DERP_HTTP", "true")
}

func main() {
	flag.Parse()

	s := &tsnet.Server{
		AuthKey:    "200",
		ControlURL: "http://localhost:3000",
		Dir:        "./tsstate/web-client",
		Hostname:   "web-client",
		Logf:       logger.Discard,
	}
	defer s.Close()

	lc, err := s.LocalClient()
	if err != nil {
		log.Fatal(err)
	}

	if *devMode {
		os.Setenv("TS_DEBUG_WEB_CLIENT_DEV", "true")
	}

	// Serve the Tailscale web client.
	ws, err := web.NewServer(web.ServerOpts{
		LocalClient: lc,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer ws.Shutdown()

	log.Printf("Serving Tailscale web client on http://%s", *addr)
	if err := http.ListenAndServe(*addr, ws); err != nil {
		if err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}
}
