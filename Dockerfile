FROM cgr.dev/chainguard/static:latest

WORKDIR /
COPY tscoordinator .
ENTRYPOINT ["/tscoordinator"]
