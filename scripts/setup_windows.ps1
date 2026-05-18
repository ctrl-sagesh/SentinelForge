# SentinelForge Windows Setup Script
# Run: powershell -ExecutionPolicy Bypass -File scripts/setup_windows.ps1

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $ProjectRoot) { $ProjectRoot = Get-Location }

Write-Host "=== SentinelForge Windows Setup ===" -ForegroundColor Cyan

# Check Python version
$pythonVersion = python --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Python 3.11+ is required but not found." -ForegroundColor Red
    exit 1
}
Write-Host "Found: $pythonVersion" -ForegroundColor Green

# Create virtual environment
if (-not (Test-Path ".venv")) {
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    python -m venv .venv
}

# Activate virtual environment
Write-Host "Activating virtual environment..." -ForegroundColor Yellow
& .venv\Scripts\Activate.ps1

# Install dependencies
Write-Host "Installing dependencies..." -ForegroundColor Yellow
pip install --upgrade pip
pip install -e ".[all]"

# Create data directories
Write-Host "Creating data directories..." -ForegroundColor Yellow
$dirs = @("data", "data/vector_db", "logs")
foreach ($dir in $dirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

# Copy .env if it doesn't exist
if (-not (Test-Path ".env")) {
    Write-Host "Creating .env from .env.example..." -ForegroundColor Yellow
    Copy-Item ".env.example" ".env"
    Write-Host "IMPORTANT: Edit .env with your configuration before running." -ForegroundColor Red
}

# Seed knowledge base
Write-Host "Seeding knowledge base..." -ForegroundColor Yellow
python -m sentinelforge.cli seed 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Knowledge base seeding skipped (ChromaDB may not be available)." -ForegroundColor Yellow
}

# Run tests
Write-Host "Running tests..." -ForegroundColor Yellow
python -m pytest tests/ -q

Write-Host ""
Write-Host "=== Setup Complete ===" -ForegroundColor Green
Write-Host "Quick start commands:" -ForegroundColor Cyan
Write-Host "  sentinelforge run --scenario brute_force    # Run a simulation"
Write-Host "  sentinelforge serve                         # Start API server"
Write-Host "  sentinelforge dashboard                     # Launch dashboard"
Write-Host "  sentinelforge evaluate                      # Run evaluation harness"
