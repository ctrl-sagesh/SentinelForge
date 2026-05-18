#!/usr/bin/env bash
# SentinelForge Linux/macOS Setup Script
# Run: bash scripts/setup_linux.sh

set -euo pipefail

echo "=== SentinelForge Setup ==="

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3.11+ is required but not found."
    exit 1
fi

PYTHON_VERSION=$(python3 --version)
echo "Found: $PYTHON_VERSION"

# Create virtual environment
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

echo "Activating virtual environment..."
source .venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install --upgrade pip
pip install -e ".[all]"

# Create data directories
echo "Creating data directories..."
mkdir -p data/vector_db logs

# Copy .env if it doesn't exist
if [ ! -f ".env" ]; then
    echo "Creating .env from .env.example..."
    cp .env.example .env
    echo "IMPORTANT: Edit .env with your configuration before running."
fi

# Seed knowledge base
echo "Seeding knowledge base..."
python -m sentinelforge.cli seed 2>/dev/null || \
    echo "Knowledge base seeding skipped (ChromaDB may not be available)."

# Run tests
echo "Running tests..."
python -m pytest tests/ -q

echo ""
echo "=== Setup Complete ==="
echo "Quick start commands:"
echo "  sentinelforge run --scenario brute_force    # Run a simulation"
echo "  sentinelforge serve                         # Start API server"
echo "  sentinelforge dashboard                     # Launch dashboard"
echo "  sentinelforge evaluate                      # Run evaluation harness"
