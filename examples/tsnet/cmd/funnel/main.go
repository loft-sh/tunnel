// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The tsnet-funnel server demonstrates how to use tsnet with Funnel.
//
// To use it, generate an auth key from the Tailscale admin panel and
// run the demo with the key:
//
//	TS_AUTHKEY=<yourkey> go run tsnet-funnel.go
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
)

func init() {
	// envknob.Setenv("TS_DEBUG_USE_DERP_HTTP", "true")
}

func main() {
	flag.Parse()
	s := &tsnet.Server{
		AuthKey:    "100",
		ControlURL: "http://localhost:3000",
		Dir:        "./tsstate/funnel-demo",
		Hostname:   "fun",
		Logf:       logger.Discard,
	}
	defer s.Close()

	ln, err := s.ListenFunnel("tcp", ":443")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	fmt.Printf("Listening on https://%v\n", s.CertDomains()[0])

	err = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "<html><body><h1>Hello, internet!</h1>")
	}))
	log.Fatal(err)
}
