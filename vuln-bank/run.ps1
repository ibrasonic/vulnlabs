# run.ps1 - launch vuln-bank locally.
# Installs Node.js via winget if missing (with consent), runs npm install,
# seeds the SQLite DB, starts the server.

$ErrorActionPreference = 'Stop'
$AppRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $AppRoot

function Test-Command($name) {
    return $null -ne (Get-Command $name -ErrorAction SilentlyContinue)
}

if (-not (Test-Command 'node')) {
    Write-Host '[run.ps1] Node.js is not installed.' -ForegroundColor Yellow
    if (Test-Command 'winget') {
        $ans = Read-Host '[run.ps1] Install Node.js LTS via winget? [Y/n]'
        if ($ans -eq '' -or $ans -match '^[Yy]') {
            winget install --id OpenJS.NodeJS.LTS -e --accept-source-agreements --accept-package-agreements
        } else {
            Write-Host 'Aborting. Install Node.js then re-run.'; exit 1
        }
    } else {
        Write-Host 'winget not available. Install Node.js manually from https://nodejs.org/' ; exit 1
    }
    # PATH from winget may need a new shell; try refreshing.
    $env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
    if (-not (Test-Command 'node')) {
        Write-Host 'Node.js installed but not on PATH for this shell. Open a new PowerShell and re-run.'
        exit 1
    }
}

Write-Host '[run.ps1] Node version:' (node --version)
Write-Host '[run.ps1] NPM version: ' (npm --version)

if (-not (Test-Path (Join-Path $AppRoot 'node_modules'))) {
    Write-Host '[run.ps1] Installing dependencies...' -ForegroundColor Cyan
    npm install --no-fund --no-audit
}

$env:PORT = if ($env:PORT) { $env:PORT } else { '3001' }
$env:HOST = if ($env:HOST) { $env:HOST } else { '0.0.0.0' }

Write-Host ''
Write-Host '===================================================' -ForegroundColor Green
Write-Host '  vuln-bank starting' -ForegroundColor Green
Write-Host "  http://localhost:$($env:PORT)/" -ForegroundColor Green
Write-Host '  Login: alice.chen / Password123!' -ForegroundColor Green
Write-Host '  Admin: julie.morgan / Admin2024!' -ForegroundColor Green
Write-Host '  See VULNERABILITIES.txt for exploit recipes.' -ForegroundColor Green
Write-Host '===================================================' -ForegroundColor Green
Write-Host ''

node server.js
