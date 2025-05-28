.PHONY: build run test lint docker-build docker-run docker-push clean deps help migrate

# Variables
APP_NAME=prism-auth-service
VERSION=latest
DOCKER_IMAGE=lumina/$(APP_NAME):$(VERSION)
DOCKER_REGISTRY=registry.lumina.com
GO_VERSION=1.24
PORT=8080

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

deps: ## Download dependencies
	go mod download
	go mod verify
	go mod tidy

build: ## Build the application
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-w -s" -o bin/$(APP_NAME) cmd/server/main.go

build-local: ## Build for local development
	go build -o bin/$(APP_NAME) cmd/server/main.go

run: ## Run the application locally
	go run cmd/server/main.go

run-with-env: ## Run with environment file
	set -a && source .env && set +a && go run cmd/server/main.go

test: ## Run tests
	go test -v -race -coverprofile=coverage.out ./...

test-coverage: ## Run tests with coverage report
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

test-integration: ## Run integration tests
	go test -v -tags=integration ./...

test-watch: ## Run tests in watch mode (requires entr)
	find . -name "*.go" | entr -r go test ./...

lint: ## Run linters
	golangci-lint run --config .golangci.yml

lint-fix: ## Run linters with auto-fix
	golangci-lint run --fix --config .golangci.yml

format: ## Format code
	gofmt -s -w .
	goimports -w .

vet: ## Run go vet
	go vet ./...

security: ## Run security scanner
	gosec ./...

docker-build: ## Build Docker image
	docker build -f docker/Dockerfile -t $(DOCKER_IMAGE) .
	docker tag $(DOCKER_IMAGE) $(DOCKER_IMAGE)-$(shell git rev-parse --short HEAD)

docker-run: ## Run Docker container
	docker run -it --rm \
		-p $(PORT):8080 \
		-e DATABASE_URL=postgres://user:pass@host.docker.internal:5432/prism_auth \
		-e JWT_SECRET=your-jwt-secret-key \
		-e SERVER_PORT=8080 \
		--name $(APP_NAME) \
		$(DOCKER_IMAGE)

docker-run-detached: ## Run Docker container in background
	docker run -d \
		-p $(PORT):8080 \
		-e DATABASE_URL=postgres://user:pass@host.docker.internal:5432/prism_auth \
		-e JWT_SECRET=your-jwt-secret-key \
		-e SERVER_PORT=8080 \
		--name $(APP_NAME) \
		$(DOCKER_IMAGE)

docker-stop: ## Stop Docker container
	docker stop $(APP_NAME) || true
	docker rm $(APP_NAME) || true

docker-push: ## Push Docker image to registry
	docker tag $(DOCKER_IMAGE) $(DOCKER_REGISTRY)/$(DOCKER_IMAGE)
	docker push $(DOCKER_REGISTRY)/$(DOCKER_IMAGE)

docker-compose-up: ## Start services with docker-compose
	docker-compose up -d

docker-compose-down: ## Stop services with docker-compose
	docker-compose down

docker-compose-logs: ## View docker-compose logs
	docker-compose logs -f $(APP_NAME)

migrate-up: ## Run database migrations up
	migrate -path migrations -database "$(DATABASE_URL)" up

migrate-down: ## Run database migrations down
	migrate -path migrations -database "$(DATABASE_URL)" down

migrate-create: ## Create new migration (usage: make migrate-create NAME=create_new_table)
	migrate create -ext sql -dir migrations -seq $(NAME)

migrate-force: ## Force migration version (usage: make migrate-force VERSION=1)
	migrate -path migrations -database "$(DATABASE_URL)" force $(VERSION)

dev-setup: ## Setup development environment
	@echo "Setting up development environment..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
	@echo "Development tools installed!"

clean: ## Clean build artifacts
	rm -rf bin/
	rm -f coverage.out coverage.html
	docker rmi $(DOCKER_IMAGE) 2>/dev/null || true

clean-all: ## Clean everything including Docker images
	make clean
	docker system prune -f
	docker volume prune -f

logs: ## View application logs (if running in container)
	docker logs -f $(APP_NAME)

health-check: ## Check service health
	curl -f http://localhost:$(PORT)/health || echo "Service not running"

install: ## Install the application binary
	go install cmd/server/main.go

benchmark: ## Run benchmarks
	go test -bench=. -benchmem ./...

mod-update: ## Update all dependencies
	go get -u ./...
	go mod tidy

generate: ## Generate code (if using go generate)
	go generate ./...

audit: ## Run security audit
	go list -json -deps ./... | nancy sleuth

release: build docker-build ## Build and prepare for release
	@echo "Release $(VERSION) ready!"
	@echo "Binary: bin/$(APP_NAME)"
	@echo "Docker image: $(DOCKER_IMAGE)"

deploy-staging: ## Deploy to staging environment
	@echo "Deploying to staging..."
	# Add your staging deployment commands here

deploy-prod: ## Deploy to production environment
	@echo "Deploying to production..."
	# Add your production deployment commands here

.DEFAULT_GOAL := help
