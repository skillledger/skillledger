# Multi-stage build for skillledger-log transparency log personality.
# Produces a minimal static binary with no CGO dependencies.

FROM golang:1.26-alpine AS builder

WORKDIR /build

# Cache dependency downloads.
COPY go.mod go.sum ./
RUN go mod download

# Build the binary with reproducible build flags.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /skillledger-log ./cmd/skillledger-log

# Runtime stage: minimal Alpine image.
FROM alpine:3.21

RUN apk add --no-cache curl ca-certificates

COPY --from=builder /skillledger-log /usr/local/bin/skillledger-log

# Create default storage directory for POSIX log data.
RUN mkdir -p /data/tlog

EXPOSE 2025

HEALTHCHECK --interval=5s --timeout=3s CMD curl -f http://localhost:2025/checkpoint || exit 1

ENTRYPOINT ["/usr/local/bin/skillledger-log"]
