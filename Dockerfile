# build stage
FROM golang:1.16-alpine AS build-env
RUN apk add --no-cache \
    git \
    make \
    gcc \
    libc-dev \
    tzdata \
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
FROM alpine:3.12

LABEL org.opencontainers.image.source="https://github.com/0xERR0R/blocky" \
      org.opencontainers.image.url="https://github.com/0xERR0R/blocky" \
      org.opencontainers.image.title="DNS proxy as ad-blocker for local network"

RUN apk add --no-cache bind-tools tini
COPY --from=build-env /src/bin/blocky /app/blocky

# the timezone data:
COPY --from=build-env /usr/share/zoneinfo /usr/share/zoneinfo
# the tls certificates:
COPY --from=build-env /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

HEALTHCHECK --interval=1m --timeout=3s CMD dig @127.0.0.1 -p 53 healthcheck.blocky +tcp || exit 1

WORKDIR /app

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/app/blocky","--config","/app/config.yml"]
