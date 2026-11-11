FROM golang:1.26-alpine3.24 AS network-helper
WORKDIR /build/backend
COPY backend/go.mod ./
COPY backend/internal/networkpolicy ./internal/networkpolicy
COPY backend/internal/management ./internal/management
COPY backend/cmd/vpn-network ./cmd/vpn-network
COPY backend/internal/vpnauthwire ./internal/vpnauthwire
COPY backend/cmd/vpn-auth ./cmd/vpn-auth
COPY backend/internal/statswire ./internal/statswire
COPY backend/cmd/vpn-stats ./cmd/vpn-stats
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/vpn-network ./cmd/vpn-network
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/vpn-auth ./cmd/vpn-auth

RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/vpn-stats ./cmd/vpn-stats

FROM alpine:3.24
LABEL org.opencontainers.image.licenses="GPL-3.0-or-later"
COPY LICENSE /usr/share/licenses/tunnelslate/LICENSE
ARG OPENVPN_VERSION=2.7.7-r0
RUN apk add --no-cache "openvpn=${OPENVPN_VERSION}" iptables iproute2 && \
    addgroup -g 10001 desk && adduser -D -H -u 10001 -G desk desk
COPY --chmod=755 docker/openvpn/entrypoint.sh /usr/local/bin/start-openvpn
COPY --chmod=755 docker/openvpn/render-config.sh /usr/local/bin/render-vpn-config
COPY --chmod=755 docker/openvpn/configure-mss.sh /usr/local/bin/configure-vpn-mss
COPY --from=network-helper /out/vpn-network /usr/local/bin/vpn-network
COPY --from=network-helper /out/vpn-auth /usr/local/bin/vpn-auth
COPY --from=network-helper /out/vpn-stats /usr/local/bin/vpn-stats
COPY --chmod=755 docker/openvpn/learn-address.sh /usr/local/bin/desk-learn-address
COPY --chmod=755 docker/openvpn/client-connect.sh /usr/local/bin/desk-client-connect
COPY --chmod=755 docker/openvpn/client-disconnect.sh /usr/local/bin/desk-client-disconnect
ENTRYPOINT ["/usr/local/bin/start-openvpn"]
