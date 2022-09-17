# prepare build environment
FROM --platform=$BUILDPLATFORM ghcr.io/gythialy/golang-cross-builder:v1.19.1-0 AS build

# required arguments(target will be through buildx)
ARG VERSION
ARG BUILD_TIME
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT

# arguments to environment
ENV CGO_ENABLED=0
ENV GOOS=$TARGETOS
ENV GOARCH=$TARGETARCH

# add blocky user
RUN echo "blocky:x:100:65533:Blocky User,,,:/app:/sbin/nologin" > /tmp/blocky_passwd
#adduser -home /app -shell /sbin/nologin blocky && \
#    tail -n 1 /etc/passwd > /tmp/blocky_passwd

# set working directory
WORKDIR /go/src

# add source
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg \
    go mod download

ADD . .

# build binary
RUN --mount=type=cache,target=/root/.cache/go-build \ 
    --mount=type=cache,target=/go/pkg \
    chmod +x ./docker/*.sh && \
    export GOARM=${TARGETVARIANT##*v} && \
    export CC=$(./docker/getenv_cc.sh) && \
    ./docker/printenv.sh && \
    go generate ./... && \
    go build \
    -tags static,osusergo,netgo \
    -v \
    -ldflags="-linkmode external -extldflags -static -X github.com/0xERR0R/blocky/util.Version=${VERSION} -X github.com/0xERR0R/blocky/util.BuildTime=${BUILD_TIME}" \
    -o /bin/blocky
# ,sharing=locked

RUN setcap 'cap_net_bind_service=+ep' /bin/blocky 
RUN chown 100 /bin/blocky

# final stage
FROM scratch

LABEL org.opencontainers.image.source="https://github.com/0xERR0R/blocky" \
      org.opencontainers.image.url="https://github.com/0xERR0R/blocky" \
      org.opencontainers.image.title="DNS proxy as ad-blocker for local network"

WORKDIR /app

COPY --from=build /tmp/blocky_passwd /etc/passwd
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /bin/blocky /app/blocky

USER blocky

ENV BLOCKY_CONFIG_FILE=/app/config.yml

ENTRYPOINT ["/app/blocky"]

HEALTHCHECK --interval=1m --timeout=3s CMD ["/app/blocky", "healthcheck"]
