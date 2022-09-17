#!/usr/bin/env bash

.PHONY: all clean build swagger test lint run help
.DEFAULT_GOAL := help

VERSION:=$(shell git describe --always --tags)
BUILD_TIME=$(shell date '+%Y%m%d-%H%M%S')
DOCKER_IMAGE_NAME=spx01/blocky
BINARY_NAME=blocky
BIN_OUT_DIR=bin

export PATH=$(shell go env GOPATH)/bin:$(shell echo $$PATH)

all: build test lint ## Build binary (with tests)

clean: ## cleans output directory
	$(shell rm -rf $(BIN_OUT_DIR)/*)

swagger: ## creates swagger documentation as html file
	npm install bootprint bootprint-openapi html-inline
	go run github.com/swaggo/swag/cmd/swag init -g api/api.go
	$(shell) node_modules/bootprint/bin/bootprint.js openapi docs/swagger.json /tmp/swagger/
	$(shell) node_modules/html-inline/bin/cmd.js /tmp/swagger/index.html > docs/swagger.html

serve_docs: ## serves online docs
	mkdocs serve

build:  ## Build binary
	go generate ./...
	go build -v -ldflags="-w -s -X github.com/0xERR0R/blocky/util.Version=${VERSION} -X github.com/0xERR0R/blocky/util.BuildTime=${BUILD_TIME}" -o $(BIN_OUT_DIR)/$(BINARY_NAME)$(BINARY_SUFFIX)

test:  ## run tests
	go run github.com/onsi/ginkgo/v2/ginkgo -v --coverprofile=coverage.txt --covermode=atomic -cover ./...

race: ## run tests with race detector
	go run github.com/onsi/ginkgo/v2/ginkgo --race ./...

lint: ## run golangcli-lint checks
	go run github.com/golangci/golangci-lint/cmd/golangci-lint run --timeout 5m

run: build ## Build and run binary
	./$(BIN_OUT_DIR)/$(BINARY_NAME)

fmt: ## gofmt and goimports all go files
	find . -name '*.go' | while read -r file; do gofmt -w -s "$$file"; goimports -w "$$file"; done

docker-build:  ## Build docker image 
	docker buildx \
	build -o type=docker \
	--cache-from type=registry,ref=ghcr.io/0xerr0r/blocky:buildcache \
	--build-arg VERSION=${VERSION} \
	--build-arg BUILD_TIME=${BUILD_TIME} \
	--network=host -t ${DOCKER_IMAGE_NAME} .

help:  ## Shows help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
