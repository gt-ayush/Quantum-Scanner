.PHONY: help build run test clean fmt lint vet docker-build docker-run docker-compose-up docker-compose-down db-init db-migrate db-backup

# Default target
help:
	@echo "Quantum Sentinel AI - Makefile"
	@echo ""
	@echo "Build:"
	@echo "  make build          Build the binary"
	@echo "  make build-docker   Build Docker image"
	@echo ""
	@echo "Run:"
	@echo "  make run            Run locally (requires PostgreSQL)"
	@echo "  make docker-run     Run in Docker"
	@echo "  make docker-compose-up   Start docker-compose stack"
	@echo ""
	@echo "Development:"
	@echo "  make fmt            Format code"
	@echo "  make vet            Run go vet"
	@echo "  make lint           Run linter"
	@echo "  make test           Run tests"
	@echo ""
	@echo "Database:"
	@echo "  make db-init        Initialize database"
	@echo "  make db-backup      Backup database"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean          Remove build artifacts"
	@echo "  make docker-clean   Remove Docker containers/images"

# Build the binary
build:
	@echo "Building quantum-sentinel-api..."
	mkdir -p bin
	go build -o bin/quantum-sentinel-api ./cmd/api
	@echo "Build complete: bin/quantum-sentinel-api"

# Build optimized binary for production
build-prod:
	@echo "Building production binary..."
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
		-ldflags="-s -w -X main.Version=1.0.0" \
		-o bin/quantum-sentinel-api ./cmd/api
	@echo "Production build complete"

# Run locally
run: build
	@echo "Starting Quantum Sentinel API..."
	@echo "Make sure PostgreSQL is running and environment variables are set:"
	@echo "  export DB_CONNECTION_URL=postgresql://..."
	@echo "  export JWT_SECRET=your-secret-key"
	./bin/quantum-sentinel-api

# Run with environment variables
run-dev:
	export DB_CONNECTION_URL="postgresql://postgres:password@localhost:5432/quantum_sentinel" && \
	export JWT_SECRET="test-secret-key" && \
	go run ./cmd/api

# Build Docker image
docker-build:
	@echo "Building Docker image..."
	docker build -t quantum-sentinel:latest .
	docker tag quantum-sentinel:latest quantum-sentinel:1.0.0
	@echo "Docker image built: quantum-sentinel:latest"

# Run Docker container
docker-run: docker-build
	@echo "Starting Docker container..."
	docker run -p 8080:8080 \
		-e DB_CONNECTION_URL="postgresql://postgres:password@localhost:5432/quantum_sentinel" \
		-e JWT_SECRET="your-secret-key" \
		quantum-sentinel:latest

# Docker compose - start
docker-compose-up:
	@echo "Starting docker-compose stack..."
	docker-compose up -d
	@echo "API running on: http://localhost:8080"
	@echo "Database: localhost:5432"
	@echo ""
	@echo "Test health: curl http://localhost:8080/health"

# Docker compose - stop
docker-compose-down:
	@echo "Stopping docker-compose stack..."
	docker-compose down

# Docker compose - logs
docker-compose-logs:
	docker-compose logs -f api

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...
	@echo "Format complete"

# Run go vet
vet:
	@echo "Running go vet..."
	go vet ./...
	@echo "Go vet check passed"

# Lint code (requires golangci-lint)
lint:
	@echo "Running linter..."
	@if command -v golangci-lint > /dev/null; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

# Run tests
test:
	@echo "Running tests..."
	go test -v -race -cover ./...

# Test coverage
test-coverage:
	@echo "Generating coverage report..."
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Initialize database
db-init:
	@echo "Database initialization is automatic on API startup"
	@echo "Connect to verify: psql postgresql://postgres@localhost/quantum_sentinel"

# Backup database
db-backup:
	@echo "Backing up database..."
	@mkdir -p backups
	@pg_dump quantum_sentinel | gzip > backups/quantum_sentinel_$(shell date +%Y%m%d_%H%M%S).sql.gz
	@echo "Backup complete"

# Restore database from backup
db-restore:
	@echo "Usage: make db-restore BACKUP=backups/quantum_sentinel_YYYYMMDD_HHMMSS.sql.gz"
	@if [ -n "$(BACKUP)" ]; then \
		gunzip < $(BACKUP) | psql quantum_sentinel; \
		echo "Restore complete"; \
	fi

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf bin/
	rm -f coverage.out coverage.html
	go clean -cache -testcache
	@echo "Clean complete"

# Remove Docker resources
docker-clean:
	@echo "Removing Docker images and containers..."
	docker-compose down -v
	docker rmi quantum-sentinel:latest quantum-sentinel:1.0.0 2>/dev/null || true
	@echo "Docker cleanup complete"

# Full clean
clean-all: clean docker-clean
	@echo "Full cleanup complete"

# Code quality check
check: fmt vet lint test
	@echo "All checks passed!"

# Development setup
setup:
	@echo "Setting up development environment..."
	go mod download
	go mod tidy
	@if ! command -v golangci-lint > /dev/null; then \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	fi
	@echo "Setup complete"

# Show statistics
stats:
	@echo "Code Statistics:"
	@echo "Go files: $$(find . -name '*.go' -type f | wc -l)"
	@echo "Lines of code: $$(find . -name '*.go' -type f -exec wc -l {} + | tail -1)"
	@echo "Go packages: $$(go list ./... | wc -l)"

# Update dependencies
deps-update:
	@echo "Updating dependencies..."
	go get -u ./...
	go mod tidy
	@echo "Dependencies updated"

# View API documentation (if you have swagger)
docs:
	@echo "Quantum Sentinel AI - API Documentation"
	@echo ""
	@echo "Quick links:"
	@echo "- README: README.md"
	@echo "- Configuration: CONFIGURATION.md"
	@echo "- Quick Start: QUICKSTART.md"
	@echo "- Implementation: IMPLEMENTATION_SUMMARY.md"
	@echo ""
	@echo "API Endpoints:"
	@echo "- GET  /health                              (public)"
	@echo "- POST /api/v1/scan                         (Admin, Operator)"
	@echo "- POST /api/v1/batch-scan                   (Admin, Operator)"
	@echo "- GET  /api/v1/cbom                         (Checker, Operator, Auditor)"
	@echo "- GET  /api/v1/history                      (Auditor)"
	@echo "- GET  /api/v1/risk-summary                 (Checker, Auditor)"
	@echo "- GET  /api/v1/analyze/cipher-suite         (Checker, Auditor)"
