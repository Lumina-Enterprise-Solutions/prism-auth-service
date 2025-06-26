# Makefile for prism-auth-service

# Define colors for output
GREEN  := $(shell tput -T screen setaf 2)
YELLOW := $(shell tput -T screen setaf 3)
RESET  := $(shell tput -T screen sgr0)

# Service specific configuration
SERVICE_NAME=prism-auth-service

# Go configuration
GO_CMD=go
GO_TEST=$(GO_CMD) test
GO_LINT=golangci-lint run

# Docker configuration
# Assumes this Makefile is run from the service's directory
DOCKER_COMPOSE=docker-compose -f ../../docker-compose.yml

.PHONY: help build test test-integration lint tidy

help:
	@echo "------------------------------------------------------------------"
	@echo " ${YELLOW}Makefile for $(SERVICE_NAME)${RESET}"
	@echo "------------------------------------------------------------------"
	@echo " ${GREEN}build${RESET}              - Build or rebuild the service's Docker image."
	@echo " ${GREEN}test${RESET}               - Run unit tests for this service (skips integration tests)."
	@echo " ${GREEN}test-integration${RESET}   - Run all tests for this service, including integration tests."
	@echo " ${GREEN}lint${RESET}               - Run the Go linter on this service."
	@echo " ${GREEN}tidy${RESET}               - Tidy the Go module for this service."
	@echo "------------------------------------------------------------------"
	@echo " Note: Integration tests require all services to be running ('make -C ../.. up')."

build:
	@echo "${GREEN}Building $(SERVICE_NAME) image...${RESET}"
	@$(DOCKER_COMPOSE) build $(SERVICE_NAME)

test:
	@echo "${GREEN}Running unit tests for $(SERVICE_NAME)...${RESET}"
	@$(GO_TEST) -v -short -race ./...

test-integration:
	@echo "${GREEN}Running integration tests for $(SERVICE_NAME)...${RESET}"
	@echo "${YELLOW}Make sure dependent services are running via 'make -C ../.. up' first.${RESET}"
	@# Memastikan skrip dapat dieksekusi dan kemudian menjalankannya.
	@chmod +x ./scripts/test-integration.sh
	@./scripts/test-integration.sh

lint:
	@echo "${GREEN}Linting $(SERVICE_NAME)...${RESET}"
	@$(GO_LINT)

tidy:
	@echo "${GREEN}Tidying $(SERVICE_NAME) go.mod...${RESET}"
	@go mod tidy
