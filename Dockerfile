# Multi-stage build: compiles the dashboard and the Go server from source.
# Produces the same minimal distroless runtime image as the upstream
# goreleaser-based build, but without requiring a pre-built binary in the
# build context (needed for source-based builders like DigitalOcean App Platform).

# ---- Stage 1: dashboard (React + Vite) ----
FROM node:20-alpine AS dashboard
WORKDIR /src/web/dashboard
COPY web/dashboard/package.json web/dashboard/package-lock.json ./
RUN npm ci
# vite.config.ts aliases @repo-assets -> ../../assets
COPY assets /src/assets
COPY web/dashboard/ ./
RUN npm run build

# ---- Stage 2: server (Go) ----
FROM golang:1.25-alpine AS builder
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# internal/dashboardui embeds ./dist via go:embed
COPY --from=dashboard /src/web/dashboard/dist ./internal/dashboardui/dist
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X github.com/mcpjungle/mcpjungle/pkg/version.Version=${VERSION}" \
    -o /out/mcpjungle .

# ---- Stage 3: runtime ----
FROM gcr.io/distroless/base

# OCI image labels
LABEL org.opencontainers.image.source="https://github.com/mcpjungle/mcpjungle"
LABEL org.opencontainers.image.description="MCPJungle - Self-hosted MCP Gateway for developers and enterprises"
LABEL org.opencontainers.image.title="MCPJungle"
LABEL org.opencontainers.image.vendor="mcpjungle"

COPY --from=builder /out/mcpjungle /mcpjungle

EXPOSE 8080
ENTRYPOINT ["/mcpjungle"]

# Run the Registry Server by default
CMD ["start"]
