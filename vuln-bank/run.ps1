# run.ps1 — single-command lab launcher.
#
# Requires Docker Desktop (or Docker Engine + compose plugin) on PATH.  Spins
# up the full bank + MySQL stack and tails the bank container logs.  Press
# Ctrl+C to stop tailing; the stack keeps running in the background until you
# explicitly stop it with:
#
#     docker compose down            # stop, keep data
#     docker compose down -v         # stop and wipe the MySQL volume
#
# Re-seed without losing the image cache:  docker compose down -v; ./run.ps1

$ErrorActionPreference = 'Stop'
$AppRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $AppRoot

function Test-Command($name) {
    return $null -ne (Get-Command $name -ErrorAction SilentlyContinue)
}

if (-not (Test-Command 'docker')) {
    Write-Host '[run.ps1] Docker is not installed or not on PATH.' -ForegroundColor Red
    Write-Host '          Install Docker Desktop from https://www.docker.com/products/docker-desktop'
    Write-Host '          and re-run this script.'
    exit 1
}

Write-Host '[run.ps1] docker version:' -ForegroundColor Cyan
docker --version
docker compose version

Write-Host ''
Write-Host '===================================================' -ForegroundColor Green
Write-Host '  vuln-bank — bringing up MySQL + Express stack' -ForegroundColor Green
Write-Host '  Login:  alice.chen   / Password123!' -ForegroundColor Green
Write-Host '  Admin:  julie.morgan / Admin2024!' -ForegroundColor Green
Write-Host '  Lab:    http://localhost:3001/' -ForegroundColor Green
Write-Host '  See VULNERABILITIES.txt for exploit recipes.' -ForegroundColor Green
Write-Host '===================================================' -ForegroundColor Green
Write-Host ''

docker compose up -d --build

Write-Host ''
Write-Host '[run.ps1] Stack is up.  Tailing bank logs (Ctrl+C to detach)...' -ForegroundColor Cyan
docker compose logs -f bank
