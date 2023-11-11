.PHONY: all clean generate build test e2e-test lint run fmt docker-build help
.DEFAULT_GOAL:=help

VERSION?=$(shell git describe --always --tags)
BUILD_TIME?=$(shell date --iso-8601=seconds)
DOC_PATH?="main"
DOCKER_IMAGE_NAME=spx01/blocky

BINARY_NAME:=blocky
BIN_OUT_DIR?=bin

GOARCH?=$(shell go env GOARCH)
GOARM?=$(shell go env GOARM)

GO_BUILD_FLAGS?=-v
GO_BUILD_LD_FLAGS:=\
	-w \
	-s \
	-X github.com/0xERR0R/blocky/util.Version=${VERSION} \
	-X github.com/0xERR0R/blocky/util.BuildTime=$(shell date -d "${BUILD_TIME}" '+%Y%m%d-%H%M%S') \
	-X github.com/0xERR0R/blocky/util.Architecture=${GOARCH}${GOARM}

GO_BUILD_OUTPUT:=$(BIN_OUT_DIR)/$(BINARY_NAME)$(BINARY_SUFFIX)

# define version of golangci-lint here. If defined in tools.go, go mod perfoms automatically downgrade to older version which doesn't work with golang >=1.18
GOLANG_LINT_VERSION=v1.54.2

GINKGO_PROCS?=-p

export PATH=$(shell go env GOPATH)/bin:$(shell echo $$PATH)

all: build test lint ## Build binary (with tests)

clean: ## cleans output directory
	rm -rf $(BIN_OUT_DIR)/*

serve_docs: ## serves online docs
	pip install mkdocs-material
	mkdocs serve

generate: ## Go generate
ifdef GO_SKIP_GENERATE
	$(info skipping go generate)
else
	go generate ./...
endif

build: generate ## Build binary
	go build $(GO_BUILD_FLAGS) -ldflags="$(GO_BUILD_LD_FLAGS)" -o $(GO_BUILD_OUTPUT)
ifdef BIN_USER
	$(info setting owner of $(GO_BUILD_OUTPUT) to $(BIN_USER))
	chown $(BIN_USER) $(GO_BUILD_OUTPUT)
endif
ifdef BIN_AUTOCAB
	$(info setting cap_net_bind_service to $(GO_BUILD_OUTPUT))
	setcap 'cap_net_bind_service=+ep' $(GO_BUILD_OUTPUT)
endif

test: ## run tests
	go run github.com/onsi/ginkgo/v2/ginkgo --label-filter="!e2e" --coverprofile=coverage.txt --covermode=atomic --cover -r ${GINKGO_PROCS}
	go tool cover -html coverage.txt -o coverage.html

e2e-test: ## run e2e tests
	docker buildx build \
		--build-arg VERSION=blocky-e2e \
		--network=host \
		-o type=docker \
		-t blocky-e2e \
		.
	go run github.com/onsi/ginkgo/v2/ginkgo --label-filter="e2e" --timeout 15m --flake-attempts 1 e2e

race: ## run tests with race detector
	go run github.com/onsi/ginkgo/v2/ginkgo --label-filter="!e2e" --race -r ${GINKGO_PROCS}

lint: fmt ## run golangcli-lint checks
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANG_LINT_VERSION) run --timeout 5m

run: build ## Build and run binary
	./$(BIN_OUT_DIR)/$(BINARY_NAME)

fmt: ## gofmt and goimports all go files
	go run mvdan.cc/gofumpt -l -w -extra .
	find . -name '*.go' -exec go run golang.org/x/tools/cmd/goimports -w {} +

docker-build: generate ## Build docker image
	docker buildx build \
		--build-arg VERSION=${VERSION} \
		--build-arg BUILD_TIME=${BUILD_TIME} \
		--build-arg DOC_PATH=${DOC_PATH} \
		--network=host \
		-o type=docker \
		-t ${DOCKER_IMAGE_NAME} \
		.

help:  ## Shows help
	@grep -E '^[0-9a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
