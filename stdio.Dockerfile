# Multi-stage build producing the "stdio" variant of the MCPJungle image.
# Same build stages as ./Dockerfile, but the runtime image includes Node.js
# and uv so MCPJungle can launch STDIO MCP servers that rely on `npx` / `uvx`.
# Use this variant when registering local/STDIO MCP servers on the gateway.

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

# ---- Stage 3: runtime with uv + Node.js (for STDIO MCP servers) ----
FROM ghcr.io/astral-sh/uv:debian

# OCI image labels
LABEL org.opencontainers.image.source="https://github.com/mcpjungle/mcpjungle"
LABEL org.opencontainers.image.description="MCPJungle - Self-hosted MCP Gateway for developers and enterprises"
LABEL org.opencontainers.image.title="MCPJungle"
LABEL org.opencontainers.image.vendor="mcpjungle"

# Install Node.js (for npx-launched MCP servers)
RUN apt-get update \
    && apt-get install -y curl gnupg \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/mcpjungle /mcpjungle

EXPOSE 8080
ENTRYPOINT ["/mcpjungle"]

# Run the Registry Server by default
CMD ["start"]
