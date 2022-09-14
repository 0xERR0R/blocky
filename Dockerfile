# prepare build environment
FROM --platform=$BUILDPLATFORM golang:1-alpine AS build-env

ARG VERSION
ARG BUILD_TIME
ARG TARGETOS
ARG TARGETARCH

# add blocky user
RUN adduser -S -D -H -h /app -s /sbin/nologin blocky
RUN tail -n 1 /etc/passwd > /tmp/blocky_passwd

# add packages
RUN apk add --no-cache \
    build-base \
    linux-headers \
    coreutils \
    binutils \
    libtool \
    musl-dev \
    git \
    make \
    gcc \
    libc-dev \
    zip \
    ca-certificates \
    libcap

# setup environment
ENV CGO_ENABLED=0

# set working directory
WORKDIR /go/src

# add source
ADD . .
RUN go generate ./...

# build binary
RUN --mount=target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS=$TARGETOS \
    GOARCH=$TARGETARCH \
    go build \
    -tags static \
    -v \
    -ldflags="-linkmode external -extldflags -static -X github.com/0xERR0R/blocky/util.Version=${VERSION} -X github.com/0xERR0R/blocky/util.BuildTime=${BUILD_TIME}" \
    -o /go/src/bin/blocky

RUN setcap 'cap_net_bind_service=+ep' /go/src/bin/blocky && \
    chown blocky /go/src/bin/blocky

# final stage
FROM scratch

LABEL org.opencontainers.image.source="https://github.com/0xERR0R/blocky" \
      org.opencontainers.image.url="https://github.com/0xERR0R/blocky" \
      org.opencontainers.image.title="DNS proxy as ad-blocker for local network"

COPY --from=build /tmp/blocky_passwd /etc/passwd
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /go/src/bin/blocky /app/blocky

USER blocky
WORKDIR /app

ENV BLOCKY_CONFIG_FILE=/app/config.yml

ENTRYPOINT ["/app/blocky"]

HEALTHCHECK --interval=1m --timeout=3s CMD ["/app/blocky", "healthcheck"]
