# prepare build environment
FROM --platform=$BUILDPLATFORM golang:buster AS build

ARG VERSION
ARG BUILD_TIME
ARG TARGETOS
ARG TARGETARCH

# add blocky user
#RUN adduser -home /app -shell /sbin/nologin blocky && \
#    tail -n 1 /etc/passwd > /tmp/blocky_passwd

# add packages
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    dpkg --add-architecture armhf && \
    dpkg --add-architecture armel && \
    apt-get update && \
    apt-get --no-install-recommends install -y \
    ca-certificates \
    build-essential \
    cross-gcc-dev \
    crossbuild-essential-armhf \
    crossbuild-essential-armel

# set working directory
WORKDIR /go/src

# add source
ADD . .
RUN go generate ./...

# build binary
RUN --mount=target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    CGO_ENABLED=0 \
    GOOS=$TARGETOS \
    GOARCH=$TARGETARCH \
    go build \
    -tags static \
    -v \
    -ldflags="-linkmode external -extldflags -static -X github.com/0xERR0R/blocky/util.Version=${VERSION} -X github.com/0xERR0R/blocky/util.BuildTime=${BUILD_TIME}" \
    -o /bin/blocky

RUN setcap 'cap_net_bind_service=+ep' /bin/blocky 
    #chown blocky /bin/blocky

# final stage
FROM scratch

LABEL org.opencontainers.image.source="https://github.com/0xERR0R/blocky" \
      org.opencontainers.image.url="https://github.com/0xERR0R/blocky" \
      org.opencontainers.image.title="DNS proxy as ad-blocker for local network"

WORKDIR /app

# COPY --from=build /tmp/blocky_passwd /etc/passwd
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /bin/blocky /app/blocky

#USER blocky


ENV BLOCKY_CONFIG_FILE=/app/config.yml

ENTRYPOINT ["/app/blocky"]

HEALTHCHECK --interval=1m --timeout=3s CMD ["/app/blocky", "healthcheck"]
