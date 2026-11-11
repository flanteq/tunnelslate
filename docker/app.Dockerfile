# syntax=docker/dockerfile:1
FROM node:24-alpine3.24 AS frontend-deps
WORKDIR /build/frontend
COPY frontend/package*.json ./
RUN npm ci

FROM frontend-deps AS frontend-build
COPY frontend/ ./
RUN npm run build

FROM frontend-build AS frontend-check
CMD ["sh", "-ec", "npm run check && npm test"]

FROM golang:1.26-alpine3.24 AS backend-deps
RUN apk add --no-cache gcc musl-dev easy-rsa=3.2.5-r0 openssl
WORKDIR /build/backend
COPY backend/go.mod backend/go.sum ./
RUN go mod download

FROM backend-deps AS backend-test
COPY backend/ ./
RUN mkdir -p /usr/share/tunnelslate && chmod 755 /usr/share/tunnelslate
COPY --chmod=644 docker/openvpn/server.conf /usr/share/tunnelslate/server.conf
CMD ["go", "test", "-race", "./..."]

FROM backend-test AS backend-build
RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=1 go build -trimpath -ldflags='-s -w' -o /out/tunnelslate ./cmd/server

FROM golang:1.26-alpine3.24 AS source-locks
RUN apk add --no-cache nodejs npm
WORKDIR /source
CMD ["sh", "-ec", "cd backend && go mod tidy && gofmt -w . && cd ../frontend && npm install --package-lock-only --ignore-scripts"]

FROM alpine:3.24 AS runtime
LABEL org.opencontainers.image.licenses="GPL-3.0-or-later"
COPY LICENSE /usr/share/licenses/tunnelslate/LICENSE
RUN apk add --no-cache ca-certificates libgcc easy-rsa=3.2.5-r0 openssl su-exec && \
    addgroup -g 10001 desk && adduser -D -H -u 10001 -G desk desk
WORKDIR /app
COPY --from=backend-build /out/tunnelslate /app/tunnelslate
COPY --from=frontend-build /build/frontend/dist /app/web
RUN mkdir -p /usr/share/tunnelslate && chmod 755 /usr/share/tunnelslate
COPY --chmod=644 docker/openvpn/server.conf /usr/share/tunnelslate/server.conf
COPY --chmod=755 docker/app/entrypoint.sh /usr/local/bin/start-desk
COPY --chmod=755 docker/app/admin-command.sh /usr/local/bin/desk-admin
RUN ln -s desk-admin /usr/local/bin/create-admin && \
    ln -s desk-admin /usr/local/bin/reset-password && \
    ln -s desk-admin /usr/local/bin/reset-totp
EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/start-desk"]
CMD ["/app/tunnelslate"]
