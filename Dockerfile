FROM golang:1.26-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ARG VERSION=0.2.0
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X github.com/luminariadev/raksa-siem/internal/schema.Version=${VERSION}" \
    -o /out/raksa-siem ./cmd/raksa-siem

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /workspace
COPY --from=builder /out/raksa-siem /usr/local/bin/raksa-siem
EXPOSE 8484
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD ["/usr/local/bin/raksa-siem", "version"]
ENTRYPOINT ["/usr/local/bin/raksa-siem"]
CMD ["--help"]
