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
  golangci-lint run {{ARGS}} $@

# Check struct memory alignment and print potential improvements
[no-exit-message]
check-structalign *ARGS:
  go run github.com/dkorunic/betteralign/cmd/betteralign@latest {{ARGS}} ./...
