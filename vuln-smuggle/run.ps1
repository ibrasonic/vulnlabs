# run.ps1 - launcher for vuln-smuggle (NovaPress newsroom + Argus Edge gateway).
# Installs Node via winget if missing, npm-installs deps, then runs both
# the back-end (loopback) and the gateway (public).

param(
    [int]$Port = 3004,
    [string]$BindHost = '0.0.0.0',
    [int]$BackendPort = 3094,
    [int]$PoolSize = 1
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

function Require-Cmd($name, $wingetId) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        Write-Host "[setup] $name not found, installing $wingetId via winget..." -ForegroundColor Yellow
        winget install --id $wingetId --silent --accept-package-agreements --accept-source-agreements
        if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
            throw "$name still not on PATH. Restart your shell and retry."
        }
    }
}

Require-Cmd 'node' 'OpenJS.NodeJS.LTS'
Require-Cmd 'npm'  'OpenJS.NodeJS.LTS'

if (-not (Test-Path node_modules)) {
    Write-Host '[setup] npm install...' -ForegroundColor Yellow
    npm install --no-fund --no-audit
}

$env:GW_HOST = $BindHost
$env:GW_PORT = "$Port"
$env:BE_HOST = '127.0.0.1'
$env:BE_PORT = "$BackendPort"
$env:UP_HOST = '127.0.0.1'
$env:UP_PORT = "$BackendPort"
$env:GW_POOL = "$PoolSize"

Write-Host ''
Write-Host '=================================================================' -ForegroundColor Magenta
Write-Host (' NovaPress (vuln-smuggle)   http://localhost:' + $Port) -ForegroundColor Magenta
Write-Host '=================================================================' -ForegroundColor Magenta
Write-Host (' Public site (via Argus Edge):  http://localhost:' + $Port + '/')
Write-Host (' Direct back-end (loopback):    http://127.0.0.1:' + $BackendPort + '/')
Write-Host ''
Write-Host ' Demo accounts:'
Write-Host '   emma.kovac      / Pa55word!     (subscriber)'
Write-Host '   alice.lefebvre  / Editor2024!   (editor)'
Write-Host '   richard.hong    / Admin2024!    (admin)'
Write-Host ''
Write-Host ' The Argus Edge has the smuggling bug. /cms and /admin are'
Write-Host ' blocked on public ingress; the back-end runs with'
Write-Host ' insecureHTTPParser=true. See VULNERABILITIES.txt.'
Write-Host '=================================================================' -ForegroundColor Magenta

node server.js
