set positional-arguments

timestamp := `date +%s`

[private]
alias align := check-structalign

_default:
  @just --list

# --- Code quality ---

# Run golangci-lint for all packages
lint:
  golangci-lint run $@

# Check struct memory alignment and print potential improvements
[no-exit-message]
check-structalign *ARGS:
  go run github.com/dkorunic/betteralign/cmd/betteralign@latest {{ARGS}} ./...
