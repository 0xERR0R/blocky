.PHONY: all clean generate build test e2e-test e2e-test-coverage lint run fmt docker-build help check-tools
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
GOLANG_LINT_VERSION=v2.2.1

GINKGO_PROCS?=

export PATH=$(shell go env GOPATH)/bin:$(shell echo $$PATH)

# Tool check functions
define check_command
	@which $(1) > /dev/null 2>&1 || { echo "Error: $(1) is required but not installed. $(2)"; exit 1; }
endef

define check_go_tool
	@go list -f "{{.ImportPath}}" $(1) > /dev/null 2>&1 || { echo "Error: $(1) is required but not installed. Run: go install $(1)@latest"; exit 1; }
endef

check-go:
	$(call check_command,go,"Please install Go from https://golang.org/doc/install")

check-docker:
	$(call check_command,docker,"Please install Docker from https://docs.docker.com/get-docker/")
	@docker buildx version > /dev/null 2>&1 || { echo "Error: docker buildx is required but not installed. See https://docs.docker.com/buildx/working-with-buildx/"; exit 1; }

all: build test lint ## Build binary (with tests)

clean: ## cleans output directory
	rm -rf $(BIN_OUT_DIR)/*

serve_docs: check-docker ## serves online docs using Docker
	docker run --rm -p 8000:8000 -v $(PWD):/docs squidfunk/mkdocs-material:latest

generate: check-go ## Go generate
ifdef GO_SKIP_GENERATE
	$(info skipping go generate)
else
	go generate ./...
endif

build: check-go generate ## Build binary
	go build $(GO_BUILD_FLAGS) -ldflags="$(GO_BUILD_LD_FLAGS)" -o $(GO_BUILD_OUTPUT)
ifdef BIN_USER
	$(info setting owner of $(GO_BUILD_OUTPUT) to $(BIN_USER))
	chown $(BIN_USER) $(GO_BUILD_OUTPUT)
endif
ifdef BIN_AUTOCAB
	$(info setting cap_net_bind_service to $(GO_BUILD_OUTPUT))
	setcap 'cap_net_bind_service=+ep' $(GO_BUILD_OUTPUT)
endif

test: check-go ## run tests
	go tool ginkgo --label-filter="!e2e" --coverprofile=coverage.txt --covermode=atomic --cover -r ${GINKGO_PROCS}
	go tool cover -html coverage.txt -o coverage.html

e2e-test: check-go check-docker ## run e2e tests
	docker buildx build \
		--build-arg VERSION=blocky-e2e \
		--build-arg BUILD_TIME=${BUILD_TIME} \
		--build-arg GOPROXY \
		--network=host \
		-o type=docker \
		-t blocky-e2e \
		.
	go tool ginkgo -p --label-filter="e2e" --timeout 15m --flake-attempts 1 e2e

e2e-test-coverage: check-go check-docker ## run e2e tests with code coverage
	@echo "Building coverage-instrumented Docker image..."
	docker buildx build \
		--build-arg VERSION=blocky-e2e-coverage \
		--build-arg BUILD_TIME=${BUILD_TIME} \
		--build-arg GOPROXY \
		--build-arg OPTS="-cover" \
		--network=host \
		-o type=docker \
		-t blocky-e2e-coverage \
		.
	@echo "Running e2e tests with coverage collection..."
	@mkdir -p coverage/e2e
	@rm -rf coverage/e2e/*
	@chmod 777 coverage/e2e
	BLOCKY_IMAGE=blocky-e2e-coverage GOCOVERDIR=$(PWD)/coverage/e2e \
		go tool ginkgo -p --label-filter="e2e" --timeout 15m --flake-attempts 1 e2e
	@echo "Converting coverage data..."
	go tool covdata textfmt -i=./coverage/e2e -o=coverage/e2e-coverage.out
	@echo ""
	@echo "Coverage report generated!"
	@echo "===================="
	@go tool cover -func=coverage/e2e-coverage.out | awk '\
		BEGIN { print "\nCoverage by package:" } \
		/^total:/ { total = $$3; next } \
		/:/ { \
			split($$1, parts, ":"); \
			file = parts[1]; \
			n = split(file, path, "/"); \
			if (n > 1) { \
				pkg = path[1]; \
				for (i = 2; i < n; i++) pkg = pkg "/" path[i]; \
			} else { \
				pkg = "."; \
			} \
			gsub(/%/, "", $$3); \
			sum[pkg] += $$3; \
			count[pkg]++; \
		} \
		END { \
			for (pkg in sum) { \
				printf "%-60s %6.1f%%\n", pkg, sum[pkg]/count[pkg]; \
			} \
			print "------------------------------------------------------------"; \
			printf "%-60s %s\n", "TOTAL", total; \
		}' | sort
	@echo ""
	@echo "View full coverage report:"
	@echo "  - HTML: go tool cover -html=coverage/e2e-coverage.out"
	@echo "  - Text: go tool cover -func=coverage/e2e-coverage.out"

race: check-go ## run tests with race detector
	go tool ginkgo --label-filter="!e2e" --race -r ${GINKGO_PROCS}

lint: check-go fmt ## run golangcli-lint checks
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANG_LINT_VERSION) run --timeout 5m

run: build ## Build and run binary
	./$(BIN_OUT_DIR)/$(BINARY_NAME)

fmt: check-go ## gofmt and goimports all go files
	go tool gofumpt -l -w -extra .
	find . -name '*.go' -exec go tool goimports -w {} +

docker-build: check-docker generate ## Build docker image
	docker buildx build \
		--build-arg VERSION=${VERSION} \
		--build-arg BUILD_TIME=${BUILD_TIME} \
		--build-arg GOPROXY \
		--build-arg DOC_PATH=${DOC_PATH} \
		--network=host \
		-o type=docker \
		-t ${DOCKER_IMAGE_NAME} \
		.

check-tools: check-go check-docker ## Check if all required tools are installed

help:  ## Shows help
	@grep -E '^[0-9a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
