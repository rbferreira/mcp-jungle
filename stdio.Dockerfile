# Multi-stage build producing the "stdio" variant of the MCPJungle image.
# Same build stages as ./Dockerfile, but the runtime image includes Node.js
# and uv so MCPJungle can launch STDIO MCP servers that rely on `npx` / `uvx`.
# Use this variant when registering local/STDIO MCP servers on the gateway.

# ---- Stage 1: dashboard (React + Vite) ----
FROM node:22-alpine AS dashboard
WORKDIR /src/web/dashboard
COPY web/dashboard/package.json web/dashboard/package-lock.json ./
RUN npm ci
# vite.config.ts aliases @repo-assets -> ../../assets
COPY assets /src/assets
COPY web/dashboard/ ./
RUN npm run build

# ---- Stage 2: server (Go) ----
FROM golang:1.25.13-alpine AS builder
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
# Copy only uv's static executables into the slim Node image. The derived
# uv:debian image includes a full Python/build toolchain that the gateway does
# not need and materially expands its vulnerability surface.
FROM ghcr.io/astral-sh/uv:0.12.5 AS uv
FROM node:22-alpine

# OCI image labels
LABEL org.opencontainers.image.source="https://github.com/mcpjungle/mcpjungle"
LABEL org.opencontainers.image.description="MCPJungle - Self-hosted MCP Gateway for developers and enterprises"
LABEL org.opencontainers.image.title="MCPJungle"
LABEL org.opencontainers.image.vendor="mcpjungle"

# Keep npm current because npx executes third-party MCP packages at runtime.
# npm 12.0.2 still bundles three older transitive packages with published
# high-severity fixes, so replace those exact bundled copies in the same layer.
RUN apk add --no-cache coreutils \
    && npm install --global npm@12.0.2 \
    && mkdir -p /tmp/npm-patches/brace-expansion /tmp/npm-patches/ip-address /tmp/npm-patches/tar \
    && cd /tmp/npm-patches \
    && npm pack --silent brace-expansion@5.0.9 ip-address@10.3.1 tar@7.5.21 \
    && tar -xzf brace-expansion-5.0.9.tgz --strip-components=1 -C brace-expansion \
    && tar -xzf ip-address-10.3.1.tgz --strip-components=1 -C ip-address \
    && tar -xzf tar-7.5.21.tgz --strip-components=1 -C tar \
    && rm -rf /usr/local/lib/node_modules/npm/node_modules/brace-expansion \
              /usr/local/lib/node_modules/npm/node_modules/ip-address \
              /usr/local/lib/node_modules/npm/node_modules/tar \
    && cp -R brace-expansion ip-address tar /usr/local/lib/node_modules/npm/node_modules/ \
    && rm -rf /tmp/npm-patches
COPY --from=uv /uv /uvx /bin/

COPY --from=builder /out/mcpjungle /mcpjungle

USER node
WORKDIR /home/node

EXPOSE 8080
ENTRYPOINT ["/mcpjungle"]

# Run the Registry Server by default
CMD ["start"]
