# build stage
FROM golang:1.17-alpine AS build-env
RUN apk add --no-cache \
    git \
    make \
    gcc \
    libc-dev \
    zip \
    ca-certificates

ENV GO111MODULE=on \
    CGO_ENABLED=0
    
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

# add source
ADD . .

ARG opts
RUN env ${opts} make build

# final stage
FROM alpine:3.15

LABEL org.opencontainers.image.source="https://github.com/0xERR0R/blocky" \
      org.opencontainers.image.url="https://github.com/0xERR0R/blocky" \
      org.opencontainers.image.title="DNS proxy as ad-blocker for local network"

COPY --from=build-env /src/bin/blocky /app/blocky
RUN apk add --no-cache ca-certificates bind-tools tini tzdata libcap && \
    adduser -S -D -H -h /app -s /sbin/nologin blocky && \
    setcap 'cap_net_bind_service=+ep' /app/blocky

HEALTHCHECK --interval=1m --timeout=3s CMD dig @127.0.0.1 -p 53 healthcheck.blocky +tcp +short || exit 1

USER blocky
WORKDIR /app

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/app/blocky","--config","/app/config.yml"]
