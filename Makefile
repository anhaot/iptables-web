.PHONY: build package run test script-test integration-test clean dev help install install-binary uninstall

APP_NAME := iptables-web
AGENT_NAME := iptables-web-agent
BIN_DIR := bin
BUILD_PROCS ?= 2

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build Go binary for Linux
	@mkdir -p $(BIN_DIR)
	@rm -rf assets/web && cp -r web assets/web
	GOMAXPROCS=$(BUILD_PROCS) CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -p=$(BUILD_PROCS) -buildvcs=false -ldflags="-s -w" -o $(BIN_DIR)/$(APP_NAME) ./cmd/server
	GOMAXPROCS=$(BUILD_PROCS) CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -p=$(BUILD_PROCS) -buildvcs=false -ldflags="-s -w" -o $(BIN_DIR)/$(AGENT_NAME) ./cmd/agent

package: ## Build a tar.gz package for hosts without Go
	bash scripts/build-package.sh

run: ## Run locally (requires root)
	@rm -rf assets/web && cp -r web assets/web
	@mkdir -p data
	sudo DEV_MODE=$${DEV_MODE:-false} RULES_FILE=$${RULES_FILE:-./data/rules.json} go run ./cmd/server

test: ## Run Go tests
	@rm -rf assets/web && cp -r web assets/web
	GOMAXPROCS=$(BUILD_PROCS) go test -p=$(BUILD_PROCS) ./... -v

integration-test: ## Run isolated controller/Agent end-to-end smoke test
	bash scripts/integration-smoke.sh

script-test: ## Verify installer path safety without changing the system
	bash scripts/install-path-test.sh

clean: ## Remove build artifacts
	rm -rf $(BIN_DIR)

install: build ## Install to host system (CentOS/Ubuntu/Kylin)
	sudo bash scripts/install.sh

install-binary: ## Install from a prebuilt package directory
	sudo bash scripts/install-binary.sh

uninstall: ## Remove managed rules, service, binary, docs, and data
	sudo bash scripts/uninstall.sh

dev: ## Run in development mode
	@mkdir -p data
	DEV_MODE=true RULES_FILE=$${RULES_FILE:-./data/rules.json} go run ./cmd/server
