# build stage
FROM golang:1.14-alpine AS build-env
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

COPY go.mod .
COPY go.sum .
RUN go mod download

# add source
ADD . .

ARG opts
RUN make tools
RUN env ${opts} make build

# final stage
FROM alpine
RUN apk add --no-cache bind-tools
COPY --from=build-env /src/bin/blocky /app/blocky

# the timezone data:
COPY --from=build-env /usr/share/zoneinfo /usr/share/zoneinfo
# the tls certificates:
COPY --from=build-env /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

HEALTHCHECK --interval=1m --timeout=3s CMD dig @127.0.0.1 -p 53 healthcheck.blocky +tcp || exit 1

WORKDIR /app

ENTRYPOINT ["/app/blocky","--config","/app/config.yml"]