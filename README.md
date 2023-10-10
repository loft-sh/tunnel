# TailScale Coordinator Library

This is a library that simplifies the implementation and integration of a Tailscale control server into your Go application.

## Disclaimer

This project is not affiliated with Tailscale or Tailscale Inc., and it is not an official Tailscale or Tailscale Inc. project.

## Installation

To install the library, run the following command:

```bash
go get github.com/loft-sh/tunnel
```

## Usage

To use the library, import it into your Go code and implement the tailscale coordinator interface:

```go
package main

import (
  "net/http"

  "github.com/loft-sh/tunnel"
  "github.com/loft-sh/tunnel/mux"
)

func main() {
  coordinator := NewTSCoordinator()

  router := http.NewServeMux()
  router.Handle("/", mux.CoordinatorHandler(coordinator))

  if err := http.ListenAndServe(":3000", router); err != nil {
    panic(err)
  }
}

func NewTSCoordinator() tunnel.TailscaleCoordinator {
  // Your coordinator implementation gets instantiated here
  // ...
}
```
