.PHONY: all clean build swagger test lint run help
.DEFAULT_GOAL := help

VERSION := $(shell git describe --always --tags)
BUILD_TIME=$(shell date '+%Y%m%d-%H%M%S')
DOCKER_IMAGE_NAME="spx01/blocky"
BINARY_NAME=blocky
BIN_OUT_DIR=bin

all: test lint build ## Build binary (with tests)

clean: ## cleans output directory
	$(shell rm -rf $(BIN_OUT_DIR)/*)

swagger: ## creates swagger documentation as html file
	go get github.com/swaggo/swag/cmd/swag@v1.6.9
	npm install bootprint bootprint-openapi html-inline
	$(shell go env GOPATH)/bin/swag init -g api/api.go
	$(shell) node_modules/bootprint/bin/bootprint.js openapi docs/swagger.json /tmp/swagger/
	$(shell) node_modules/html-inline/bin/cmd.js /tmp/swagger/index.html > docs/swagger.html

serve_docs: ## serves online docs
	mkdocs serve

build:  ## Build binary
	go build -v -ldflags="-w -s -X blocky/cmd.version=${VERSION} -X blocky/cmd.buildTime=${BUILD_TIME}" -o $(BIN_OUT_DIR)/$(BINARY_NAME)$(BINARY_SUFFIX)

test:  ## run tests
	go test -v -coverprofile=coverage.txt -covermode=atomic -cover ./...

lint: build ## run golangcli-lint checks
	$(shell go env GOPATH)/bin/golangci-lint run

run: build ## Build and run binary
	./$(BIN_OUT_DIR)/$(BINARY_NAME)

docker-build:  ## Build docker image
	docker build --network=host --tag ${DOCKER_IMAGE_NAME} .

help:  ## Shows help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
