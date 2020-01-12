.PHONY: all clean build test lint run buildMultiArchRelease docker-build dockerManifestAndPush help
.DEFAULT_GOAL := help

VERSION := $(shell git describe --always --tags)
BUILD_TIME=$(shell date '+%Y%m%d-%H%M%S')
DOCKER_IMAGE_NAME="spx01/blocky"
BINARY_NAME=blocky
BIN_OUT_DIR=bin

all: test lint build ## Build binary (with tests)

clean: ## cleans output directory
	$(shell rm -rf $(BIN_OUT_DIR)/*)

build:  ## Build binary
	go build -v -ldflags="-w -s -X main.version=${VERSION} -X main.buildTime=${BUILD_TIME}" -o $(BIN_OUT_DIR)/$(BINARY_NAME)$(BINARY_SUFFIX)

test:  ## run tests
	go test -v -cover ./...

lint: ## run golangcli-lint checks
	$(shell go env GOPATH)/bin/golangci-lint run

run: build ## Build and run binary
	./$(BIN_OUT_DIR)/$(BINARY_NAME)

buildMultiArchRelease: ## builds binary for multiple archs
	$(MAKE) build GOARCH=arm GOARM=6 BINARY_SUFFIX=_arm32v6
	$(MAKE) build GOARCH=amd64 BINARY_SUFFIX=_amd64

docker-build:  ## Build multi arch docker images
	docker build --build-arg opts="GOARCH=arm GOARM=6" --pull --tag ${DOCKER_IMAGE_NAME}:${VERSION}-arm32v6 .
	docker build --build-arg opts="GOARCH=amd64" --pull --tag ${DOCKER_IMAGE_NAME}:${VERSION}-amd64 .

dockerManifestAndPush: ## create manifest for multi arch images and push to docker hub
	docker push ${DOCKER_IMAGE_NAME}:${VERSION}-arm32v6
	docker push ${DOCKER_IMAGE_NAME}:${VERSION}-amd64

	docker manifest create ${DOCKER_IMAGE_NAME}:${VERSION} ${DOCKER_IMAGE_NAME}:${VERSION}-amd64 ${DOCKER_IMAGE_NAME}:${VERSION}-arm32v6
	docker manifest annotate ${DOCKER_IMAGE_NAME}:${VERSION} ${DOCKER_IMAGE_NAME}:${VERSION}-arm32v6 --os linux --arch arm
	docker manifest push ${DOCKER_IMAGE_NAME}:${VERSION} --purge
	docker manifest create ${DOCKER_IMAGE_NAME}:latest ${DOCKER_IMAGE_NAME}:${VERSION}-amd64 ${DOCKER_IMAGE_NAME}:${VERSION}-arm32v6
	docker manifest annotate ${DOCKER_IMAGE_NAME}:latest ${DOCKER_IMAGE_NAME}:${VERSION}-arm32v6 --os linux --arch arm
	docker manifest push ${DOCKER_IMAGE_NAME}:latest --purge

help:  ## Shows help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'