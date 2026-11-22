# syntax=docker/dockerfile:1

# ==============================================================================
# Stage 1: Build Custom CoreDNS on Alpine with CGo + libunbound
# ==============================================================================
FROM golang:alpine AS builder

ARG COREDNS_VERSION=v1.15.0
ARG UNBOUND_PLUGIN_REV=master

# Install CGo build toolchain and libunbound headers
RUN apk add --no-cache \
    git \
    make \
    gcc \
    musl-dev \
    unbound-dev \
    openssl-dev \
    ca-certificates

WORKDIR /src

# Copy local repository (plugins/securityfilter, go.mod, etc.)
COPY . /src/resolver

# Clone upstream CoreDNS at pinned release tag
RUN git clone --depth 1 --branch ${COREDNS_VERSION} https://github.com/coredns/coredns

WORKDIR /src/coredns

# Inject custom plugin.cfg
COPY plugin.cfg /src/coredns/plugin.cfg

# Wire local securityfilter plugin and pull coredns/unbound
RUN go mod edit -replace github.com/AdamBowers/Resolver=/src/resolver && \
    go get github.com/coredns/unbound@${UNBOUND_PLUGIN_REV} && \
    go generate coredns.go && \
    go mod tidy

# Compile with CGo enabled (required for libunbound bindings)
ENV CGO_ENABLED=1
ENV GOOS=linux
RUN go build -trimpath -ldflags="-s -w" -o /out/coredns .

# Fetch current IANA root hints for iterative root recursion
ADD https://www.internic.net/domain/named.root /out/root.hints

# ==============================================================================
# Stage 2: Minimal Hardened Alpine Runtime (ReadOnly=true Quadlet Ready)
# ==============================================================================
FROM alpine:latest

# Install only runtime shared libraries + IANA DNSSEC root trust anchor
RUN apk add --no-cache \
    unbound-libs \
    libssl3 \
    ca-certificates \
    dnssec-root \
    && adduser -D -H -u 65532 -s /sbin/nologin coredns

# Prepare mount points expected by dns-infra-host Quadlets
# - /etc/coredns/lists and /etc/coredns/certs: bind-mounted read-only
# - /run/coredns: mounted as tmpfs
RUN mkdir -p /etc/coredns/lists /etc/coredns/certs /run/coredns && \
    chown -R 65532:65532 /etc/coredns /run/coredns

COPY --from=builder /out/coredns /usr/local/bin/coredns
COPY --from=builder /out/root.hints /etc/coredns/root.hints

# Copy IANA root trust anchor for DNSSEC validation
RUN cp /usr/share/dnssec-root/trusted-key.key /etc/coredns/root.key && \
    chown 65532:65532 /etc/coredns/root.hints /etc/coredns/root.key

USER 65532:65532

# Standard ports (DoH 443, DoT 853, Plain 53, Health 8080, Ready 8181, Metrics 9153)
EXPOSE 53/udp 53/tcp 443/tcp 853/tcp 8080/tcp 8181/tcp 9153/tcp

ENTRYPOINT ["/usr/local/bin/coredns"]
CMD ["-conf", "/etc/coredns/Corefile"]
