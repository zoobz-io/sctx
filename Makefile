.PHONY: test test-race coverage bench bench-all lint lint-fix check ci install-tools clean help

# Default target
help:
	@echo "Available commands:"
	@echo "  make test          - Run tests"
	@echo "  make test-race     - Run tests with race detector"
	@echo "  make coverage      - Generate coverage report"
	@echo "  make bench         - Run benchmarks"
	@echo "  make bench-all     - Run all benchmarks with detailed output"
	@echo "  make lint          - Run linters"
	@echo "  make lint-fix      - Run linters with auto-fix"
	@echo "  make check         - Run tests and linters"
	@echo "  make ci            - Run full CI suite"
	@echo "  make install-tools - Install development tools"
	@echo "  make clean         - Clean generated files"

# Testing
test:
	go test -v ./...

test-race:
	go test -v -race ./...


coverage:
	go test -v -race -coverprofile=coverage.txt -covermode=atomic ./...
	go tool cover -html=coverage.txt -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Benchmarking
bench:
	go test -bench=. -benchmem -run=^$ ./...

bench-all:
	go test -bench=. -benchmem -benchtime=10s -run=^$ ./... | tee benchmark_results.txt

# Linting
lint:
	golangci-lint run --config=.golangci.yml --timeout=5m

lint-fix:
	golangci-lint run --config=.golangci.yml --timeout=5m --fix

# Combined checks
check: test lint

# Full CI run
ci: clean
	@echo "Running full CI suite..."
	@echo "1. Running tests with race detector..."
	@$(MAKE) test-race
	@echo ""
	@echo "2. Running linters..."
	@$(MAKE) lint
	@echo ""
	@echo "3. Running benchmarks..."
	@$(MAKE) bench
	@echo ""
	@echo "4. Generating coverage..."
	@$(MAKE) coverage
	@echo ""
	@echo "✅ CI suite completed successfully!"

# Tools installation
install-tools:
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.61.0
	@echo "✅ Tools installed successfully!"

# Cleanup
clean:
	rm -f coverage.txt coverage.html
	rm -f benchmark_results.txt
	find . -name "*.test" -delete
	find . -name "*.out" -delete
	go clean -cache

