# syntax=docker/dockerfile:1

# ----------- stage: ca-certs
# get newest certificates in seperate stage for caching
FROM --platform=$BUILDPLATFORM alpine:3 AS ca-certs
RUN --mount=type=cache,target=/var/cache/apk \
  apk update && \
  apk add ca-certificates

# update certificates and use the apk ones if update fails
RUN --mount=type=cache,target=/etc/ssl/certs \
  update-ca-certificates 2>/dev/null || true

# ----------- stage: build
FROM --platform=$BUILDPLATFORM ghcr.io/kwitsch/ziggoimg AS build

# required arguments
ARG VERSION
ARG BUILD_TIME

# download packages
# bind mount go.mod and go.sum
# use cache for go packages
RUN --mount=type=bind,source=go.sum,target=go.sum \
  --mount=type=bind,source=go.mod,target=go.mod \
  --mount=type=cache,target=/root/.cache/go-build \ 
  --mount=type=cache,target=/go/pkg \
  go mod download

# setup go
ENV GO_SKIP_GENERATE=1\
  GO_BUILD_FLAGS="-tags static -v " \
  BIN_USER=100\
  BIN_AUTOCAB=1 \
  BIN_OUT_DIR="/bin"

# build binary 
# bind mount source code
# use cache for go packages
RUN --mount=type=bind,target=. \
  --mount=type=cache,target=/root/.cache/go-build \ 
  --mount=type=cache,target=/go/pkg \
  make build

# ----------- stage: final
FROM scratch

ARG VERSION
ARG BUILD_TIME
ARG DOC_PATH

LABEL org.opencontainers.image.title="blocky" \
  org.opencontainers.image.vendor="0xERR0R" \
  org.opencontainers.image.licenses="Apache-2.0" \
  org.opencontainers.image.version="${VERSION}" \
  org.opencontainers.image.created="${BUILD_TIME}" \
  org.opencontainers.image.description="Fast and lightweight DNS proxy as ad-blocker for local network with many features" \
  org.opencontainers.image.url="https://github.com/0xERR0R/blocky#readme" \
  org.opencontainers.image.source="https://github.com/0xERR0R/blocky" \
  org.opencontainers.image.documentation="https://0xerr0r.github.io/blocky/${DOC_PATH}/"



USER 100
WORKDIR /app

COPY --link --from=ca-certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --link --from=build /bin/blocky /app/blocky

ENV BLOCKY_CONFIG_FILE=/app/config.yml

ENTRYPOINT ["/app/blocky"]

HEALTHCHECK --start-period=1m --timeout=3s CMD ["/app/blocky", "healthcheck"]
