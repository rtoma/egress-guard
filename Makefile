.PHONY: build test clean run docker-build help

BINARY_NAME=egress-proxy
DOCKER_IMAGE=k8s-egress-guard:latest

## build: Build the egress proxy binary
build:
	@echo "Building $(BINARY_NAME)..."
	@go build -o $(BINARY_NAME) cmd/main.go
	@echo "✓ Build complete: $(BINARY_NAME)"

## test: Run all tests
test:
	@echo "Running tests..."
	@go test ./... -v

## test-cover: Run tests with coverage report
test-cover:
	@echo "Running tests with coverage..."
	@go test ./... -cover

## clean: Remove build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -f $(BINARY_NAME)
	@go clean
	@echo "✓ Clean complete"

## run: Run the proxy locally with example config
run: build
	@echo "Starting egress proxy..."
	@CONFIGMAP_PATH=./egress-policy.yaml LOG_LEVEL=DEBUG ./$(BINARY_NAME)

## docker-build: Build Docker image
docker-build:
	@echo "Building Docker image $(DOCKER_IMAGE)..."
	@docker build -t $(DOCKER_IMAGE) .
	@echo "✓ Docker build complete: $(DOCKER_IMAGE)"

## fmt: Format Go code
fmt:
	@echo "Formatting code..."
	@go fmt ./...
	@echo "✓ Format complete"

## vet: Run go vet
vet:
	@echo "Running go vet..."
	@go vet ./...
	@echo "✓ Vet complete"

## tidy: Tidy Go modules
tidy:
	@echo "Tidying Go modules..."
	@go mod tidy
	@echo "✓ Tidy complete"

## all: Build, test, and vet
all: fmt vet test build

## help: Display this help message
help:
	@echo "Available targets:"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'

.DEFAULT_GOAL := help
