.PHONY: test test-race test-integration test-bench test-all bench lint lint-fix coverage clean all help check ci install-tools install-hooks

.DEFAULT_GOAL := help

## help: Display available commands
help:
	@echo "sctx Development Commands"
	@echo "========================="
	@grep -E '^## [a-zA-Z_-]+:' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ": "}; {printf "  make %-18s %s\n", substr($$1, 4), $$2}'

## test: Run unit tests with race detector
test:
	@echo "Running tests..."
	@go test -tags=testing -v -race ./...

## test-race: Run unit tests with race detector (alias)
test-race: test

## test-integration: Run integration tests
test-integration:
	@echo "Running integration tests..."
	@go test -tags=integration,testing -v ./testing/integration/...

## test-bench: Run performance benchmarks
test-bench:
	@echo "Running benchmarks..."
	@go test -tags=testing -v -bench=. -benchmem ./testing/benchmarks/...

## test-all: Run all tests (unit + integration)
test-all: test test-integration
	@echo "All tests passed!"

## bench: Run benchmarks (legacy alias)
bench:
	@echo "Running benchmarks..."
	@go test -tags=testing -bench=. -benchmem -benchtime=1s ./...

## lint: Run linters
lint:
	@echo "Running linters..."
	@golangci-lint run --config=.golangci.yml --timeout=5m

## lint-fix: Run linters with auto-fix
lint-fix:
	@echo "Running linters with auto-fix..."
	@golangci-lint run --config=.golangci.yml --timeout=5m --fix

## coverage: Generate coverage report (HTML)
coverage:
	@echo "Generating coverage report..."
	@go test -tags=testing -coverprofile=coverage.out -race ./...
	@go tool cover -html=coverage.out -o coverage.html
	@go tool cover -func=coverage.out | tail -1
	@echo "Coverage report generated: coverage.html"

## clean: Remove generated files
clean:
	@echo "Cleaning..."
	@rm -f coverage.out coverage.html coverage.txt
	@rm -f benchmark_results.txt
	@find . -name "*.test" -delete
	@find . -name "*.prof" -delete
	@find . -name "*.out" -delete

## install-tools: Install required development tools
install-tools:
	@echo "Installing development tools..."
	@go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.7.2

## install-hooks: Install git hooks
install-hooks:
	@echo "Installing git hooks..."
	@mkdir -p .git/hooks
	@echo '#!/bin/sh' > .git/hooks/pre-commit
	@echo 'make check' >> .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "Git hooks installed."

## tidy: Tidy all module dependencies
tidy:
	@echo "Tidying root module..."
	@go mod tidy
	@echo "Tidying testing module..."
	@cd testing && go mod tidy

## check: Run tests and lint (quick check)
check: test lint
	@echo "All checks passed!"

## ci: Full CI simulation (all tests + lint + coverage)
ci: clean lint test test-integration coverage
	@echo "Full CI simulation complete!"

## all: Run tests and lint
all: test lint
