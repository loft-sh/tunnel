# Tailscale Coordinator Library

This is a library that simplifies the implementation and integration of a control
server for Tailscale into your Go application.

## Disclaimer

This project is not affiliated with Tailscale or Tailscale Inc., and it is not an
official Tailscale or Tailscale Inc. project.

## Installation

You can install the library using the `go get` command:

```bash
go get github.com/loft-sh/tunnel
```

## Usage

There are two main ways to use this library: as a standalone library in your Go
code, or as an in-memory coordinator for end-to-end testing.

### Using the Library in Your Go Code

To use the library in your Go code, you'll need to import it and implement the
Tailscale coordinator interface.

```go
package main

import (
  "net/http"

  "github.com/loft-sh/tunnel"
  "github.com/loft-sh/tunnel/handlers"
)

func main() {
  coordinator := NewCoordinator()

  router := http.NewServeMux()
  router.Handle("/", handlers.CoordinatorHandler(coordinator))

  if err := http.ListenAndServe(":3000", router); err != nil {
    panic(err)
  }
}

func NewCoordinator() tunnel.Coordinator {
  // Your coordinator implementation gets instantiated here
  // ...
}
```

### Using the In-Memory Coordinator

We also provide an in-memory control server, which is useful for running end-to-end
tests in a continuous integration or test environment. This server comes with
pre-configured profiles and nodes.

You can find an example of this server in the [examples/coordinator/](./examples/coordinator/)
directory.

To configure the server, edit the [config file](./examples/coordinator/config.json).
Then, run the server with the following commands:

```bash
cd examples/coordinator
go run server.go
```

## Inspiration

This project was inspired by open-source Tailscale control server implementations
such as [Headscale](https://headscale.net) and [Ionscale](https://jsiebens.github.io/ionscale/).
