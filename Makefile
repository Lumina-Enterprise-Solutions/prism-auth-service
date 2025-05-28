.PHONY: build run test clean deps docker-build docker-run docker-stop migrate help

# Variables
SERVICE_NAME=prism-auth-service
DOCKER_IMAGE=$(SERVICE_NAME):latest
DOCKER_COMPOSE_FILE=docker-compose.yml

# Default target
help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Development
deps: ## Install dependencies
	go mod download
	go mod tidy

build: ## Build the application
	go build -o bin/$(SERVICE_NAME) cmd/server/main.go

run: ## Run the application locally
	go run cmd/server/main.go

test: ## Run tests
	go test -v ./...

test-coverage: ## Run tests with coverage
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

clean: ## Clean build artifacts
	rm -rf bin/
	rm -f coverage.out coverage.html

# Database
migrate-up: ## Run database migrations up
	@echo "Running migrations..."
	# Add your migration command here

migrate-down: ## Run database migrations down
	@echo "Rolling back migrations..."
	# Add your migration rollback command here

# Docker
docker-build: ## Build Docker image
	docker build -t $(DOCKER_IMAGE) -f docker/Dockerfile .

docker-run: ## Run with Docker Compose
	docker-compose -f $(DOCKER_COMPOSE_FILE) up -d

docker-stop: ## Stop Docker Compose services
	docker-compose -f $(DOCKER_COMPOSE_FILE) down

docker-logs: ## View Docker Compose logs
	docker-compose -f $(DOCKER_COMPOSE_FILE) logs -f

docker-clean: ## Clean Docker resources
	docker-compose -f $(DOCKER_COMPOSE_FILE) down -v
	docker image prune -f

# Linting and formatting
fmt: ## Format Go code
	go fmt ./...

lint: ## Run golangci-lint
	golangci-lint run

# Security
security-scan: ## Run security scan with gosec
	gosec ./...

# Development helpers
dev-setup: ## Setup development environment
	cp .env.example .env
	@echo "Please update .env file with your configuration"

dev-db: ## Start only database services
	docker-compose -f $(DOCKER_COMPOSE_FILE) up -d postgres redis

dev-db-stop: ## Stop database services
	docker-compose -f $(DOCKER_COMPOSE_FILE) stop postgres redis
