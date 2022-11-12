# ----------- stage: ca-certs
# get newest certificates in seperate stage for caching
FROM --platform=$BUILDPLATFORM alpine:3.16 AS ca-certs
RUN apk add --no-cache ca-certificates

# update certificates and use the apk ones if update fails
RUN --mount=type=cache,target=/etc/ssl/certs \
    update-ca-certificates 2>/dev/null || true

# ----------- stage: zig-env
# zig compiler is used for CGO cross compilation
# even though CGO is disabled it is used in the os and net package
FROM --platform=$BUILDPLATFORM ghcr.io/euantorano/zig:master AS zig-env

# ----------- stage: build
FROM --platform=$BUILDPLATFORM golang:1-alpine AS build

# required arguments
ARG VERSION
ARG BUILD_TIME

# auto provided by Docker
# https://docs.docker.com/engine/reference/builder/#automatic-platform-args-in-the-global-scope
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT

# set working directory
WORKDIR /go/src

# download packages
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg \
    go mod download

# add source
COPY . .

# setup go & zig as CGO compiler
COPY --from=zig-env /usr/local/bin/zig /usr/local/bin/zig
ENV PATH="/usr/local/bin/zig:${PATH}" \
    CC="zigcc" \
    CXX="zigcpp" \
    CGO_ENABLED=0 \
    GOOS="linux" \
    GOARCH=$TARGETARCH \
    GO_SKIP_GENERATE=1\
    GO_BUILD_FLAGS="-tags static -v " \
    BIN_USER=100\
    BIN_AUTOCAB=1 \
    BIN_OUT_DIR="/bin"

# add make & libcap
RUN apk add --no-cache make libcap

# build binary 
RUN --mount=type=bind,target=. \
    --mount=type=cache,target=/root/.cache/go-build \ 
    --mount=type=cache,target=/go/pkg \
    make build GOARM=${TARGETVARIANT##*v}

# ----------- stage: final
FROM scratch

LABEL org.opencontainers.image.source="https://github.com/0xERR0R/blocky" \
      org.opencontainers.image.url="https://github.com/0xERR0R/blocky" \
      org.opencontainers.image.title="DNS proxy as ad-blocker for local network"

USER 100
WORKDIR /app

COPY --from=ca-certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /bin/blocky /app/blocky

ENV BLOCKY_CONFIG_FILE=/app/config.yml

ENTRYPOINT ["/app/blocky"]

HEALTHCHECK --interval=1m --timeout=3s CMD ["/app/blocky", "healthcheck"]
