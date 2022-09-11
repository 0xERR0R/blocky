# build stage
FROM golang:1-alpine AS build-env
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
RUN chown blocky /src/bin/blocky

# get all required files and build a root directory
FROM scratch AS combine-env

COPY --from=build-env /tmp/blocky_passwd /etc/passwd
COPY --from=build-env /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build-env /src/bin/blocky /app/blocky

# final stage
FROM scratch

LABEL org.opencontainers.image.source="https://github.com/0xERR0R/blocky" \
      org.opencontainers.image.url="https://github.com/0xERR0R/blocky" \
      org.opencontainers.image.title="DNS proxy as ad-blocker for local network"

COPY --from=combine-env / /

USER blocky
WORKDIR /app

ENV BLOCKY_CONFIG_FILE=/app/config.yml

ENTRYPOINT ["/app/blocky"]

HEALTHCHECK --interval=1m --timeout=3s CMD ["/app/blocky", "healthcheck"]
