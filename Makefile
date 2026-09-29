.PHONY: all clean generate generate-check build test fuzz check-fork-additions check-fork-additions-sync e2e-image e2e-test e2e-test-baseline e2e-test-coverage release-image-snapshot release-image-smoke lint run fmt docker-build docker-push bump-minor bump-point deploy helm-deploy version help check-tools check-goreleaser sync-handbook
.DEFAULT_GOAL:=help

VERSION:=$(shell cat VERSION)
BUILD_TIME?=$(shell date -u '+%Y-%m-%dT%H:%M:%S%z')
DOC_PATH?="main"

DOCKER_REGISTRY?=ghcr.io/chrissnell
DOCKER_TAG:=v$(VERSION)
GIT_REMOTE:=chrissnell

# Helm config
HELM_CHART:=packaging/helm/blockasaurus
HELM_RELEASE:=blockasaurus
HELM_NAMESPACE:=blockasaurus
HELM_VALUES?=values.yaml

HANDBOOK_SRC:=docs/handbook/
HANDBOOK_DEST?=/Volumes/NFS/static-sites/chrissnell.com/software/blockasaurus

BINARY_NAME:=blockasaurus
BIN_OUT_DIR?=bin

GOARCH?=$(shell go env GOARCH)
GOARM?=$(shell go env GOARM)

GO_BUILD_FLAGS?=-v
GO_BUILD_LD_FLAGS:=\
	-w \
	-s \
	-X github.com/0xERR0R/blocky/util.Version=${VERSION} \
	-X github.com/0xERR0R/blocky/util.BuildTime=$(shell date -j -f '%Y-%m-%dT%H:%M:%S%z' "${BUILD_TIME}" '+%Y%m%d-%H%M%S' 2>/dev/null || date -d "${BUILD_TIME}" '+%Y%m%d-%H%M%S' 2>/dev/null || echo "${BUILD_TIME}") \
	-X github.com/0xERR0R/blocky/util.Architecture=${GOARCH}${GOARM}

GO_BUILD_OUTPUT:=$(BIN_OUT_DIR)/$(BINARY_NAME)$(BINARY_SUFFIX)

# define version of golangci-lint here. If defined in tools.go, go mod perfoms automatically downgrade to older version which doesn't work with golang >=1.18
GOLANG_LINT_VERSION=v2.12.2

GINKGO_PROCS?=

# Fuzzing. Fuzz target seed corpora run as ordinary tests on every `make test`;
# this is the opt-in discovery mode that actively generates new inputs. `go test
# -fuzz` only fuzzes one target in one package per invocation, so `make fuzz`
# loops over every Fuzz* target in FUZZ_PKGS, time-boxing each at FUZZ_TIME.
FUZZ_TIME?=30s
FUZZ_PKGS?=./config ./util ./lists/parsers

# Parallelism and suite deadline for the e2e tests. e2e specs are dominated by
# container startup and health-check waits rather than CPU, so oversubscribing
# beyond the core count improves wall-clock time. Both are overridable because
# the CI runner is smaller and slower than a dev box: see the e2e job in
# .github/workflows/ci.yml for what it pins and why.
GINKGO_E2E_PROCS?=-p
GINKGO_E2E_TIMEOUT?=15m

# Image the e2e suite runs against. e2e/containers.go defaults to upstream's
# `blocky-e2e` and only overrides it from BLOCKY_IMAGE, so the rebranded tag we
# build here has to be exported, not just passed to `docker build` - otherwise
# every spec asks the daemon for an image that was never built.
E2E_IMAGE?=blockasaurus-e2e
E2E_COVERAGE_IMAGE?=$(E2E_IMAGE)-coverage

# Recorded set of e2e specs that are known to fail, and the Ginkgo machine-
# readable report the recorded set is compared against. See the header of
# tools/e2ebaseline/main.go and docs/UPSTREAM_SYNC.md §3a for why a baseline
# exists rather than either a green suite or no suite.
E2E_BASELINE?=e2e/failing-baseline.txt
E2E_JSON_REPORT?=e2e-report.json

E2E_GINKGO=go tool ginkgo ${GINKGO_E2E_PROCS} --label-filter="e2e" \
	--timeout $(GINKGO_E2E_TIMEOUT) --flake-attempts 1 \
	--json-report=$(E2E_JSON_REPORT) e2e

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

check-goreleaser:
	$(call check_command,goreleaser,"Please install GoReleaser from https://goreleaser.com/install/")
	$(call check_command,jq,"Required by scripts/smoke-release-image.sh to read dist/artifacts.json")

all: build test lint ## Build binary (with tests)

clean: ## cleans output directory
	rm -rf $(BIN_OUT_DIR)/*

serve_docs: check-docker ## serves online docs using Docker
	docker run --rm -p 8000:8000 -v $(PWD):/docs squidfunk/mkdocs-material:latest

generate: check-go ## Go generate
ifdef GO_SKIP_GENERATE
	$(info skipping go generate)
else
	go tool mockery
	go generate ./...
endif

generate-check: check-go ## Verify generated files (mocks, enums, config schema) are up to date
	go tool mockery
	go generate ./...
	@git diff --exit-code || { echo "generated files are out of date; run 'make generate' and commit the result"; exit 1; }

build: check-go generate ## Build binary
	go build $(GO_BUILD_FLAGS) -ldflags="$(GO_BUILD_LD_FLAGS)" -o $(GO_BUILD_OUTPUT)
ifdef BIN_USER
	$(info setting owner of $(GO_BUILD_OUTPUT) to $(BIN_USER))
	chown $(BIN_USER) $(GO_BUILD_OUTPUT)
endif
ifdef BIN_AUTOCAB
	$(info setting cap_net_bind_service (permitted) on $(GO_BUILD_OUTPUT))
	setcap 'cap_net_bind_service=+p' $(GO_BUILD_OUTPUT)
endif

test: check-go check-fork-additions ## run tests
	go tool ginkgo --label-filter="!e2e" --coverprofile=coverage.txt --covermode=atomic --cover -r ${GINKGO_PROCS}
	go tool cover -html coverage.txt -o coverage.html

fuzz: check-go ## run each fuzz target for FUZZ_TIME (default 30s); e.g. make fuzz FUZZ_TIME=2m
	@set -e; \
	for pkg in $(FUZZ_PKGS); do \
		for target in $$(go test -list '^Fuzz' $$pkg | grep '^Fuzz'); do \
			echo "==> fuzzing $$target in $$pkg for $(FUZZ_TIME)"; \
			go test -run '^$$' -fuzz "^$$target$$" -fuzztime $(FUZZ_TIME) $$pkg; \
		done; \
	done

# NOTE: this is the image `make docker-build` builds, not the one the release
# ships. release.yml runs goreleaser, which uses Dockerfile.goreleaser - a
# `FROM scratch` wrapper around an already-compiled binary, so it has no ui
# stage. `make release-image-snapshot` + `make release-image-smoke` are what
# build and exercise that one; see docs/UPSTREAM_SYNC.md §11 for what still
# differs between the two images and what no longer does.
e2e-image: check-go check-docker ## build the container image the e2e suite runs against
	docker buildx build \
		--build-arg VERSION=$(VERSION) \
		--build-arg BUILD_TIME=${BUILD_TIME} \
		--build-arg GOPROXY \
		--network=host \
		-o type=docker \
		-t $(E2E_IMAGE) \
		.

e2e-test: e2e-image ## run e2e tests; fails on any failing spec
	BLOCKY_IMAGE=$(E2E_IMAGE) $(E2E_GINKGO)

# What CI runs. Same suite, but the pass/fail decision comes from the diff
# against E2E_BASELINE instead of from the raw failure count, so a new failure
# and a newly-fixed spec both break the build while the recorded set does not.
# The `-` is load-bearing: ginkgo's own exit status is expected to be non-zero
# while the baseline is non-empty, and e2ebaseline is what adjudicates it.
e2e-test-baseline: e2e-image ## run e2e tests, failing only when the failure set differs from the baseline
	-BLOCKY_IMAGE=$(E2E_IMAGE) $(E2E_GINKGO)
	go run ./tools/e2ebaseline -report $(E2E_JSON_REPORT) -baseline $(E2E_BASELINE)

e2e-test-coverage: check-go check-docker ## run e2e tests with code coverage
	@echo "Building coverage-instrumented Docker image..."
	docker buildx build \
		--build-arg VERSION=$(E2E_COVERAGE_IMAGE) \
		--build-arg BUILD_TIME=${BUILD_TIME} \
		--build-arg GOPROXY \
		--build-arg OPTS="-cover" \
		--network=host \
		-o type=docker \
		-t $(E2E_COVERAGE_IMAGE) \
		.
	@echo "Running e2e tests with coverage collection..."
	@mkdir -p coverage/e2e
	@rm -rf coverage/e2e/*
	@chmod 777 coverage/e2e
	BLOCKY_IMAGE=$(E2E_COVERAGE_IMAGE) GOCOVERDIR=$(PWD)/coverage/e2e \
		go tool ginkgo ${GINKGO_E2E_PROCS} --label-filter="e2e" --timeout $(GINKGO_E2E_TIMEOUT) --flake-attempts 1 e2e
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

# The image the release actually ships. `make docker-build` and the e2e suite
# build `Dockerfile`; release.yml runs goreleaser against Dockerfile.goreleaser,
# which until GRA-651 was built by nothing until a tag fired. These two targets
# are that build and its smoke test without a tag and without a push, and the
# release-image job in .github/workflows/ci.yml runs the same pair on every PR.
#
# `goreleaser release --snapshot` rather than a bare `docker buildx build -f
# Dockerfile.goreleaser`: the per-arch cross-compiled binaries, the ldflags and
# the build flags that produce the shipped image all come from .goreleaser.yml,
# so a hand-rolled buildx invocation would prove a different image.
release-image-snapshot: check-go check-docker check-goreleaser ## build the release artifacts, including the shipped image, with no tag and no push
	goreleaser release --snapshot --clean

release-image-smoke: check-docker ## start the goreleaser-built image and prove it serves DNS and the admin UI
	./scripts/smoke-release-image.sh

race: check-go ## run tests with race detector
	go tool ginkgo --label-filter="!e2e" --race -r ${GINKGO_PROCS}

check-fork-additions: ## verify no Blockasaurus-only file was dropped by an upstream merge
	@test -s .fork-additions || { \
		echo "FATAL: .fork-additions is missing or empty."; \
		echo "That file IS the guard — losing it silently disables this check."; \
		echo "Restore it from git, or regenerate per the instructions in its header."; \
		exit 1; \
	}
	@lost=0; checked=0; \
	while IFS= read -r path || [ -n "$$path" ]; do \
		case "$$path" in ''|\#*) continue;; esac; \
		checked=$$((checked + 1)); \
		if [ ! -e "$$path" ]; then \
			echo "MISSING: $$path"; lost=1; \
		elif [ ! -s "$$path" ]; then \
			echo "EMPTY:   $$path"; lost=1; \
		fi; \
	done < .fork-additions; \
	if [ $$lost -ne 0 ]; then \
		echo; \
		echo "Blockasaurus-only files were lost from the working tree."; \
		echo "An upstream merge most likely resolved a delete/modify conflict the wrong way."; \
		echo "See docs/UPSTREAM_SYNC.md."; \
		exit 1; \
	fi; \
	echo "fork additions: all $$checked files present"

check-fork-additions-sync: ## verify .fork-additions still matches reality (needs: git fetch upstream)
# One shell with `set -e` on purpose: split across recipe lines, the early
# `exit 0` below would only end its own line and make would carry on to
# compare the manifest against an empty upstream tree — reporting every
# upstream file as a missing entry, and recommending a "fix" that would pad
# the manifest with the whole upstream tree and neuter check-fork-additions.
	@set -e; \
	if ! git rev-parse --verify -q upstream/main >/dev/null 2>&1; then \
		echo "skip: upstream/main not fetched (git remote add upstream https://github.com/0xERR0R/blocky.git && git fetch upstream main)"; \
		exit 0; \
	fi; \
	tmp=$$(mktemp -d); \
	trap 'rm -rf "$$tmp"' EXIT INT TERM; \
	grep -v -e '^#' -e '^$$' .fork-additions | sort > "$$tmp/have"; \
	git ls-tree -r --name-only HEAD > "$$tmp/ours.raw"; \
	git ls-tree -r --name-only upstream/main > "$$tmp/theirs.raw"; \
	sort "$$tmp/ours.raw" > "$$tmp/ours"; \
	sort "$$tmp/theirs.raw" > "$$tmp/theirs"; \
	comm -23 "$$tmp/ours" "$$tmp/theirs" > "$$tmp/want"; \
	if ! diff -u --label .fork-additions --label .fork-additions.expected "$$tmp/have" "$$tmp/want"; then \
		echo; \
		echo ".fork-additions is stale. Regenerate it per the instructions in its header."; \
		exit 1; \
	fi; \
	echo "fork additions: manifest is in sync with upstream/main"

lint: check-go fmt ## run golangcli-lint checks
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANG_LINT_VERSION) run --timeout 5m

run: build ## Build and run binary
	./$(BIN_OUT_DIR)/$(BINARY_NAME)

fmt: check-go ## gofmt and goimports all go files
	go tool gofumpt -l -w -extra .
	find . -name '*.go' -exec go tool goimports -w {} +

docker-build: check-docker ## Build docker image tagged with VERSION
	docker build \
		--platform linux/amd64 \
		--build-arg VERSION=$(DOCKER_TAG) \
		--build-arg BUILD_TIME=${BUILD_TIME} \
		-t $(DOCKER_REGISTRY)/blockasaurus:$(DOCKER_TAG) \
		-t $(DOCKER_REGISTRY)/blockasaurus:latest \
		.

docker-push: docker-build ## Build and push docker image to ghcr.io
	docker push $(DOCKER_REGISTRY)/blockasaurus:$(DOCKER_TAG)
	docker push $(DOCKER_REGISTRY)/blockasaurus:latest
	@echo "Pushed $(DOCKER_REGISTRY)/blockasaurus:$(DOCKER_TAG)"

version: ## Show current version
	@echo $(DOCKER_TAG)

bump-minor: ## Bump minor version, commit, tag, and push
	@echo "Current version: $(VERSION)"
	$(eval NEW_VERSION := $(shell echo $(VERSION) | awk -F. '{printf "%d.%d.0", $$1, $$2+1}'))
	@echo "$(NEW_VERSION)" > VERSION
	sed -i.bak -e 's/^version: .*/version: $(NEW_VERSION)/' -e 's/^appVersion: .*/appVersion: "v$(NEW_VERSION)"/' $(HELM_CHART)/Chart.yaml
	@rm $(HELM_CHART)/Chart.yaml.bak
	@echo "New version: $(NEW_VERSION)"
	git add VERSION $(HELM_CHART)/Chart.yaml
	git commit -m "Bump version to v$(NEW_VERSION)"
	git tag "v$(NEW_VERSION)"
	git push $(GIT_REMOTE) && git push $(GIT_REMOTE) "v$(NEW_VERSION)"

bump-point: ## Bump point version, commit, tag, and push
	@echo "Current version: $(VERSION)"
	$(eval NEW_VERSION := $(shell echo $(VERSION) | awk -F. '{printf "%d.%d.%d", $$1, $$2, $$3+1}'))
	@echo "$(NEW_VERSION)" > VERSION
	sed -i.bak -e 's/^version: .*/version: $(NEW_VERSION)/' -e 's/^appVersion: .*/appVersion: "v$(NEW_VERSION)"/' $(HELM_CHART)/Chart.yaml
	@rm $(HELM_CHART)/Chart.yaml.bak
	@echo "New version: $(NEW_VERSION)"
	git add VERSION $(HELM_CHART)/Chart.yaml
	git commit -m "Bump version to v$(NEW_VERSION)"
	git tag "v$(NEW_VERSION)"
	git push $(GIT_REMOTE) && git push $(GIT_REMOTE) "v$(NEW_VERSION)"

deploy: docker-push ## Build locally, push, and deploy to Kubernetes via Helm
	helm upgrade --install $(HELM_RELEASE) $(HELM_CHART) \
		-n $(HELM_NAMESPACE) \
		-f $(HELM_VALUES) \
		--set image.tag=$(DOCKER_TAG)
	@echo "Deployed $(DOCKER_REGISTRY)/blockasaurus:$(DOCKER_TAG)"

helm-deploy: ## Deploy to Kubernetes via Helm (image already built by CI)
	helm upgrade --install $(HELM_RELEASE) $(HELM_CHART) \
		-n $(HELM_NAMESPACE) \
		-f $(HELM_VALUES) \
		--set image.tag=$(DOCKER_TAG)
	@echo "Deployed $(DOCKER_REGISTRY)/blockasaurus:$(DOCKER_TAG)"

sync-handbook: ## Rsync handbook to static site destination
	rsync -av --delete $(HANDBOOK_SRC) $(HANDBOOK_DEST)/

check-tools: check-go check-docker ## Check if all required tools are installed

help:  ## Shows help
	@grep -E '^[0-9a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
