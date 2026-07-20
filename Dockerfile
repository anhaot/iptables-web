# ===== Stage 1: Build =====
FROM golang:1.26.5-alpine AS builder

RUN apk add --no-cache git ca-certificates
WORKDIR /app

# Cache module downloads
COPY go.mod ./
RUN go mod download 2>/dev/null || true

# Copy source and build (go build fetches any missing deps)
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
	    go build -buildvcs=false -ldflags="-s -w -X main.version=docker" \
    -o /iptables-web ./cmd/server

# ===== Stage 2: Runtime =====
FROM alpine:3.20

RUN apk add --no-cache \
    iptables \
    ip6tables \
    ca-certificates \
    tzdata \
    && rm -rf /var/cache/apk/*

# Create data directory for persistent rules
RUN install -d -m 0700 /data

COPY --from=builder /iptables-web /usr/local/bin/iptables-web
COPY scripts/healthcheck.sh /usr/local/bin/healthcheck.sh
RUN chmod +x /usr/local/bin/healthcheck.sh

EXPOSE 33801

# Run as root (required by iptables) — capabilities are limited at runtime via docker-compose
ENTRYPOINT ["iptables-web"]
