.PHONY: build package run test clean docker-build docker-up docker-down help install install-binary uninstall

APP_NAME := iptables-web
BIN_DIR := bin
DOCKER_IMAGE := iptables-web:latest

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build Go binary for Linux
	@mkdir -p $(BIN_DIR)
	@rm -rf assets/web && cp -r web assets/web
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -ldflags="-s -w" -o $(BIN_DIR)/$(APP_NAME) ./cmd/server

package: ## Build a tar.gz package for hosts without Go
	bash scripts/build-package.sh

run: ## Run locally (requires root)
	@rm -rf assets/web && cp -r web assets/web
	sudo DEV_MODE=${DEV_MODE:-false} RULES_FILE=${RULES_FILE:-./data/rules.json} go run ./cmd/server

test: ## Run Go tests
	@rm -rf assets/web && cp -r web assets/web
	go test ./... -v

clean: ## Remove build artifacts
	rm -rf $(BIN_DIR)

install: build ## Install to host system (CentOS/Ubuntu/Kylin)
	sudo bash scripts/install.sh

install-binary: ## Install from a prebuilt package directory
	sudo bash scripts/install-binary.sh

uninstall: ## Remove managed rules, service, binary, docs, and data
	sudo bash scripts/uninstall.sh

docker-build: ## Build Docker image
	docker build -t $(DOCKER_IMAGE) .

docker-up: ## Start with docker-compose
	docker-compose up -d --build

docker-down: ## Stop docker-compose services
	docker-compose down

docker-logs: ## View logs
	docker-compose logs -f

docker-restart: ## Restart the service
	docker-compose restart

dev: ## Run in development mode
	DEV_MODE=true go run ./cmd/server
