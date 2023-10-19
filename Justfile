set positional-arguments

timestamp := `date +%s`

[private]
alias align := check-structalign

_default:
  @just --list

dev:
  zellij -s tunnel --layout tunnel_layout.kdl

# --- Code quality ---

# Run golangci-lint for all packages
lint *ARGS:
  golangci-lint run {{ARGS}} -- $(go work edit -json | jq -c -r '[.Use[].DiskPath] | map_values(. + "/...")[]')

# Check struct memory alignment and print potential improvements
[no-exit-message]
check-structalign *ARGS:
  go run github.com/dkorunic/betteralign/cmd/betteralign@latest {{ARGS}} ./...

# --- Go tooling ---

tidy:
  go mod tidy
  cd examples/coordinator/ && go mod tidy
