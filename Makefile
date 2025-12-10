.PHONY: help install setup run-api run-client test test-unit test-integration test-cov test-health decode-token clean

help:
	@echo "OAuth 2.0 Token Exchange Lab - Available Commands"
	@echo "=================================================="
	@echo ""
	@echo "Setup:"
	@echo "  make setup       - Create .env file from template"
	@echo "  make install     - Install Python dependencies"
	@echo ""
	@echo "Run:"
	@echo "  make run-api     - Start the protected API server"
	@echo "  make run-client  - Start the OAuth client (opens browser)"
	@echo ""
	@echo "Testing:"
	@echo "  make test        - Run all tests"
	@echo "  make test-unit   - Run only unit tests"
	@echo "  make test-integration - Run only integration tests"
	@echo "  make test-cov    - Run tests with coverage report"
	@echo "  make test-health - Test API health endpoint"
	@echo ""
	@echo "Utilities:"
	@echo "  make decode-token TOKEN=<jwt> - Decode and inspect a JWT token"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean       - Remove Python cache files"
	@echo ""

setup:
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "Created .env file. Please edit it with your Okta configuration."; \
	else \
		echo ".env file already exists. Delete it first if you want to recreate it."; \
	fi

install:
	@echo "Installing dependencies..."
	pip install -r requirements.txt
	@echo "Dependencies installed successfully!"

run-api:
	@echo "Starting Protected API Server..."
	@echo "API will be available at http://api.local.com:5000"
	@echo ""
	python api.py

run-client:
	@echo "Starting OAuth Client..."
	@echo "Follow the browser prompts to authenticate."
	@echo ""
	python client.py

test:
	@echo "Running all tests..."
	pytest

test-unit:
	@echo "Running unit tests..."
	pytest -m unit

test-integration:
	@echo "Running integration tests..."
	pytest -m integration

test-cov:
	@echo "Running tests with coverage..."
	pytest --cov=. --cov-report=term-missing --cov-report=html
	@echo ""
	@echo "Coverage report generated in htmlcov/index.html"

test-health:
	@echo "Testing API health endpoint..."
	@curl -s http://api.local.com:5000/health | python -m json.tool || echo "API not reachable. Make sure it's running with 'make run-api'"

decode-token:
	@if [ -z "$(TOKEN)" ]; then \
		echo "Error: TOKEN parameter required"; \
		echo "Usage: make decode-token TOKEN=<your-jwt-token>"; \
		exit 1; \
	fi
	python decode_token.py $(TOKEN)

clean:
	@echo "Cleaning up Python cache files..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "htmlcov" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name ".coverage" -delete 2>/dev/null || true
	@echo "Cleanup complete!"
