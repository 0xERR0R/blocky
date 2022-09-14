ARG VERSION
ARG BUILD_TIME

# prepare build environment
FROM golang:1-alpine AS build-env
ARG VERSION
ARG BUILD_TIME
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

# build blocky
FROM build-env AS build
ARG VERSION
ARG BUILD_TIME

# set working directory
WORKDIR /src

# get go modules
COPY go.mod go.sum ./
RUN go mod download

# add source
ADD . .
RUN go generate ./...

# setup environment
ENV GO111MODULE=on 
ENV CGO_ENABLED=0

# build binary
RUN --mount=type=cache,target=/root/.cache/go-build \
    go build \
    -tags static \
    -v \
    -ldflags="-linkmode external -extldflags -static -X github.com/0xERR0R/blocky/util.Version=${VERSION} -X github.com/0xERR0R/blocky/util.BuildTime=${BUILD_TIME}" \
    -o /src/bin/blocky

RUN setcap 'cap_net_bind_service=+ep' /src/bin/blocky
RUN chown blocky /src/bin/blocky

# final stage
FROM scratch

LABEL org.opencontainers.image.source="https://github.com/0xERR0R/blocky" \
      org.opencontainers.image.url="https://github.com/0xERR0R/blocky" \
      org.opencontainers.image.title="DNS proxy as ad-blocker for local network"

COPY --from=build-env /tmp/blocky_passwd /etc/passwd
COPY --from=build-env /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /src/bin/blocky /app/blocky

USER blocky
WORKDIR /app

ENV BLOCKY_CONFIG_FILE=/app/config.yml

ENTRYPOINT ["/app/blocky"]

HEALTHCHECK --interval=1m --timeout=3s CMD ["/app/blocky", "healthcheck"]
