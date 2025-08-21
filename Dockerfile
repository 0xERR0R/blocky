# syntax=docker/dockerfile:1

# ----------- stage: build
FROM golang:alpine AS build
RUN apk add --no-cache make coreutils libcap

# required arguments
ARG VERSION
ARG BUILD_TIME

ARG GOPROXY=""

COPY . .
# setup go
ENV GO_SKIP_GENERATE=1\
  GO_BUILD_FLAGS="-tags static -v " \
  BIN_USER=100\
  BIN_AUTOCAB=1 \
  BIN_OUT_DIR="/bin" \
  GOPROXY=$GOPROXY


RUN make build

# ----------- stage: final
FROM scratch

ARG VERSION
ARG BUILD_TIME
ARG DOC_PATH

LABEL org.opencontainers.image.title="blocky" \
  org.opencontainers.image.vendor="0xERR0R" \
  org.opencontainers.image.licenses="Apache-2.0" \
  org.opencontainers.image.version="${VERSION}" \
  org.opencontainers.image.created="${BUILD_TIME}" \
  org.opencontainers.image.description="Fast and lightweight DNS proxy as ad-blocker for local network with many features" \
  org.opencontainers.image.url="https://github.com/0xERR0R/blocky#readme" \
  org.opencontainers.image.source="https://github.com/0xERR0R/blocky" \
  org.opencontainers.image.documentation="https://0xerr0r.github.io/blocky/${DOC_PATH}/"



USER 100
WORKDIR /app

COPY --from=build /bin/blocky /app/blocky

ENV BLOCKY_CONFIG_FILE=/app/config.yml

ENTRYPOINT ["/app/blocky"]

HEALTHCHECK --start-period=1m --timeout=3s CMD ["/app/blocky", "healthcheck"]
