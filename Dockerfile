FROM cgr.dev/chainguard/static:latest

WORKDIR /
COPY coordinator .
ENTRYPOINT ["/coordinator"]
