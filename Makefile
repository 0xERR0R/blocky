.PHONY: all tools clean build swagger test lint run buildMultiArchRelease help
.DEFAULT_GOAL := help

VERSION := $(shell git describe --always --tags)
BUILD_TIME=$(shell date '+%Y%m%d-%H%M%S')
DOCKER_IMAGE_NAME="spx01/blocky"
BINARY_NAME=blocky
BIN_OUT_DIR=bin

tools: ## prepare build tools
	mkdir -p ~/.docker && echo "{\"experimental\": \"enabled\"}" > ~/.docker/config.json
	go get github.com/swaggo/swag/cmd/swag@v1.6.9

all: test lint build ## Build binary (with tests)

clean: ## cleans output directory
	$(shell rm -rf $(BIN_OUT_DIR)/*)

swagger:
	npm install bootprint bootprint-openapi html-inline
	$(shell go env GOPATH)/bin/swag init -g api/api.go
	$(shell) node_modules/bootprint/bin/bootprint.js openapi docs/swagger.json /tmp/swagger/
	$(shell) node_modules/html-inline/bin/cmd.js /tmp/swagger/index.html > docs/swagger.html

build:  ## Build binary
	go build -v -ldflags="-w -s -X blocky/cmd.version=${VERSION} -X blocky/cmd.buildTime=${BUILD_TIME}" -o $(BIN_OUT_DIR)/$(BINARY_NAME)$(BINARY_SUFFIX)

test:  ## run tests
	go test -v -coverprofile=coverage.txt -covermode=atomic -cover ./...

lint: build ## run golangcli-lint checks
	$(shell go env GOPATH)/bin/golangci-lint run

run: build ## Build and run binary
	./$(BIN_OUT_DIR)/$(BINARY_NAME)

buildMultiArchRelease: ## builds binary for multiple archs
	$(MAKE) build GOOS=linux GOARCH=arm GOARM=6 BINARY_SUFFIX=_${VERSION}_linux_arm32v6
	$(MAKE) build GOOS=linux GOARCH=amd64 BINARY_SUFFIX=_${VERSION}_linux_amd64
	$(MAKE) build GOOS=linux GOARCH=arm64 BINARY_SUFFIX=_${VERSION}_linux_arm64
	$(MAKE) build GOOS=windows GOARCH=amd64 BINARY_SUFFIX=_${VERSION}_windows_amd64.exe

docker-build:  ## Build docker image
	docker build --tag ${DOCKER_IMAGE_NAME} .

help:  ## Shows help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
