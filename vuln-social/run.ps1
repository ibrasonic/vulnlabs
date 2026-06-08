# run.ps1 — Pulse Social Network launcher (vuln-social).
# Installs Node via winget if missing, npm-installs deps, starts the server,
# and prints all the URLs you can hit.

param(
    [int]$Port = 3003,
    [string]$BindHost = '0.0.0.0',
    [string]$GeminiKey = $env:GEMINI_API_KEY,
    [string]$GeminiModel = $(if ($env:GEMINI_MODEL) { $env:GEMINI_MODEL } else { 'gemini-2.0-flash' })
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

# Auto-load .env if present (KEY=VALUE per line, lines starting with # ignored).
$envFile = Join-Path $root '.env'
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith('#') -and $line.Contains('=')) {
            $k, $v = $line -split '=', 2
            $k = $k.Trim(); $v = $v.Trim().Trim('"').Trim("'")
            if ($k) { Set-Item -Path "env:$k" -Value $v }
        }
    }
    if (-not $GeminiKey)   { $GeminiKey   = $env:GEMINI_API_KEY }
    if (-not $env:GEMINI_MODEL) { $env:GEMINI_MODEL = $GeminiModel } else { $GeminiModel = $env:GEMINI_MODEL }
}

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

$env:PORT = "$Port"
$env:HOST = $BindHost
if ($GeminiKey) {
    $env:GEMINI_API_KEY = $GeminiKey
    $env:GEMINI_MODEL = $GeminiModel
    Write-Host "[ai]   Using Gemini model $GeminiModel" -ForegroundColor Green
} else {
    Write-Host "[ai]   GEMINI_API_KEY not set -- /ai-summary will use deterministic stub" -ForegroundColor DarkYellow
}

Write-Host ''
Write-Host '=================================================================' -ForegroundColor Magenta
Write-Host (' Pulse Social Network (vuln-social)  http://localhost:' + $Port) -ForegroundColor Magenta
Write-Host '=================================================================' -ForegroundColor Magenta
Write-Host ' Feed:        http://localhost:' + $Port + '/'
Write-Host ' Login:       http://localhost:' + $Port + '/login   (aria / Aria2026!)'
Write-Host ' Admin:       http://localhost:' + $Port + '/admin   (admin_eli / AdminEli!1)'
Write-Host ' AI summary:  http://localhost:' + $Port + '/ai-summary'
Write-Host ' Debug:       http://localhost:' + $Port + '/debug'
Write-Host ' WS:          ws://localhost:'   + $Port + '/socket.io/'
Write-Host ''
Write-Host ' See VULNERABILITIES.txt for the full exploit catalog.'
Write-Host '=================================================================' -ForegroundColor Magenta

node server.js
