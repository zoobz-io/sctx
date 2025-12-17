.PHONY: test test-race test-integration test-bench test-all bench lint lint-fix coverage clean all help check ci install-tools

# Default target
all: test lint

# Display help
help:
	@echo "sctx Development Commands"
	@echo "========================="
	@echo ""
	@echo "Testing & Quality:"
	@echo "  make test             - Run unit tests with race detector"
	@echo "  make test-race        - Run unit tests with race detector (alias)"
	@echo "  make test-integration - Run integration tests"
	@echo "  make test-bench       - Run performance benchmarks"
	@echo "  make test-all         - Run all tests (unit + integration)"
	@echo "  make bench            - Run benchmarks (legacy alias)"
	@echo "  make lint             - Run linters"
	@echo "  make lint-fix         - Run linters with auto-fix"
	@echo "  make coverage         - Generate coverage report (HTML)"
	@echo "  make check            - Run tests and lint (quick check)"
	@echo "  make ci               - Full CI simulation (all tests + lint + coverage)"
	@echo ""
	@echo "Other:"
	@echo "  make install-tools    - Install required development tools"
	@echo "  make clean            - Clean generated files"
	@echo "  make all              - Run tests and lint (default)"

# Run tests with race detector
test:
	@echo "Running tests..."
	@go test -tags=testing -v -race ./...

# Alias for test
test-race: test

# Run integration tests
test-integration:
	@echo "Running integration tests..."
	@go test -tags=integration,testing -v ./testing/integration/...

# Run benchmarks
test-bench:
	@echo "Running benchmarks..."
	@go test -tags=testing -v -bench=. -benchmem ./testing/benchmarks/...

# Run all tests (unit + integration)
test-all: test test-integration
	@echo "All tests passed!"

# Run benchmarks (legacy alias)
bench:
	@echo "Running benchmarks..."
	@go test -tags=testing -bench=. -benchmem -benchtime=1s ./...

# Run linters
lint:
	@echo "Running linters..."
	@golangci-lint run --config=.golangci.yml --timeout=5m

# Run linters with auto-fix
lint-fix:
	@echo "Running linters with auto-fix..."
	@golangci-lint run --config=.golangci.yml --timeout=5m --fix

# Generate coverage report
coverage:
	@echo "Generating coverage report..."
	@go test -tags=testing -coverprofile=coverage.out -race ./...
	@go tool cover -html=coverage.out -o coverage.html
	@go tool cover -func=coverage.out | tail -1
	@echo "Coverage report generated: coverage.html"

# Clean generated files
clean:
	@echo "Cleaning..."
	@rm -f coverage.out coverage.html coverage.txt
	@rm -f benchmark_results.txt
	@find . -name "*.test" -delete
	@find . -name "*.prof" -delete
	@find . -name "*.out" -delete

# Install development tools
install-tools:
	@echo "Installing development tools..."
	@go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.7.2

# Quick check - run tests and lint
check: test lint
	@echo "All checks passed!"

# CI simulation - what CI runs locally
ci: clean lint test test-integration coverage
	@echo "Full CI simulation complete!"
