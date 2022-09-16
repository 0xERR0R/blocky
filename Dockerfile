# prepare build environment
FROM --platform=$BUILDPLATFORM ghcr.io/gythialy/golang-cross-builder:v1.19.1-0 AS build

ARG VERSION
ARG BUILD_TIME
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT

# add blocky user
#RUN adduser -home /app -shell /sbin/nologin blocky && \
#    tail -n 1 /etc/passwd > /tmp/blocky_passwd

# set working directory
WORKDIR /go/src

# add source
ADD . .
RUN --mount=type=cache,target=/go/pkg \
    go generate ./...

RUN if [[ "$TARGETARCH" != "arm" ]]; then export GOARM=$TARGETVARIANT; fi

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
