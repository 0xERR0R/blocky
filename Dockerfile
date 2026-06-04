# syntax=docker/dockerfile:1

# ----------- stage: build
# Pin the build stage to the native build platform and cross-compile to the
# target platform. The build is CGO-free and the final stage is `scratch`, so
# nothing ever runs in the target arch at build time - this avoids compiling the
# Go toolchain under slow QEMU emulation for the arm targets.
FROM --platform=$BUILDPLATFORM golang:alpine AS build
RUN apk add --no-cache make coreutils libcap

# Arguments needed for dependency download
ARG GOPROXY=""
ARG OPTS=""

# setup go environment
ENV GO_SKIP_GENERATE=1\
  GO_BUILD_FLAGS="-tags static -v ${OPTS}" \
  CGO_ENABLED=0 \
  BIN_USER=100\
  BIN_AUTOCAB=1 \
  BIN_OUT_DIR="/bin" \
  GOPROXY=$GOPROXY

# Copy dependency files first for better caching
COPY go.mod go.sum ./

# Download dependencies (cached layer unless go.mod/go.sum change)
RUN go mod download

# Copy source code after dependencies are cached
COPY . .

# Arguments needed for build step only
ARG VERSION
ARG BUILD_TIME

# Target platform args populated automatically by BuildKit; cross-compile to them
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT

RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOARM=${TARGETVARIANT#v} make build

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

COPY --from=build /bin/blocky /app/blocky

ENV BLOCKY_CONFIG_FILE=/app/config.yml

ENTRYPOINT ["/app/blocky"]

HEALTHCHECK --start-period=1m --timeout=3s CMD ["/app/blocky", "healthcheck"]
