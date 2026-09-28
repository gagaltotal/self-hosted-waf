# syntax=docker/dockerfile:1

# --- Stage 1: build the dashboard frontend -----------------------------
FROM node:20-alpine AS frontend-build
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# --- Stage 2: build the Go binary, with the dashboard embedded ---------
FROM golang:1.22-alpine AS backend-build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
# Replace the development placeholder with the real, built dashboard
# before compiling -- go:embed reads this directory at build time.
RUN rm -rf internal/webui/dist/*
COPY --from=frontend-build /src/web/dist/ ./internal/webui/dist/
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/waf ./cmd/waf

# --- Stage 3: minimal runtime --------------------------------------------
# distroless has no shell, no package manager, and no extra userland
# binaries, which shrinks the image's own attack surface to just the
# compiled Go binary and CA certificates (needed for the optional
# Turnstile verification call). It also already runs as a non-root user.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=backend-build /out/waf /waf
USER nonroot:nonroot
ENTRYPOINT ["/waf"]
