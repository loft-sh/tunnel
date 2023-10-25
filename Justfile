set positional-arguments

timestamp := `date +%s`

[private]
alias align := check-structalign

_default:
  @just --list

# Start a local coordinator server and derp server
dev: mkcerts
  go install tailscale.com/cmd/derper@main
  zellij -s tunnel --layout tunnel_layout.kdl

# Start three local derp servers
mesh: mkcerts
  go install tailscale.com/cmd/derper@main
  zellij -s derpmesh --layout derp_mesh.kdl

# --- Certificates ---

# Create local certificates for derp servers
mkcerts:
  mkdir -p tmp/certs
  mkcert -cert-file tmp/certs/derp-a.crt -key-file tmp/certs/derp-a.key derp-a.local derp-a
  mkcert -cert-file tmp/certs/derp-b.crt -key-file tmp/certs/derp-b.key derp-b.local derp-b
  mkcert -cert-file tmp/certs/derp-c.crt -key-file tmp/certs/derp-c.key derp-c.local derp-c

# --- Code quality ---

# Run golangci-lint for all packages
lint *ARGS:
  golangci-lint run {{ARGS}} -- $(go work edit -json | jq -c -r '[.Use[].DiskPath] | map_values(. + "/...")[]')

# Check struct memory alignment and print potential improvements
[no-exit-message]
check-structalign *ARGS:
  go run github.com/dkorunic/betteralign/cmd/betteralign@latest {{ARGS}} ./...

# --- Go tooling ---

# Go mod tidy the repo and examples
tidy:
  go mod tidy
  cd examples/coordinator/ && go mod tidy
