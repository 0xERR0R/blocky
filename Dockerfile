# build stage
FROM golang:1-alpine AS build-env
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

ENV GO111MODULE=on \
    CGO_ENABLED=0
    
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

# add source
ADD . .

ARG opts
RUN env ${opts} make build-static
RUN setcap 'cap_net_bind_service=+ep' /src/bin/blocky

RUN adduser -S -D -H -u 10001 -h /app -s /sbin/nologin blocky

# final stage
FROM scratch

LABEL org.opencontainers.image.source="https://github.com/0xERR0R/blocky" \
      org.opencontainers.image.url="https://github.com/0xERR0R/blocky" \
      org.opencontainers.image.title="DNS proxy as ad-blocker for local network"

COPY --from=build-env /src/bin/blocky /app/blocky
COPY --from=build-env /etc/passwd /etc/passwd

# HEALTHCHECK --interval=1m --timeout=3s CMD dig @127.0.0.1 -p 53 healthcheck.blocky +tcp +short || exit 1

USER blocky
WORKDIR /app

ENTRYPOINT ["/app/blocky"]
CMD ["--config ${CONFIG_FILE:-/app/config.yml}"]
