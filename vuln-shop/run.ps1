# run.ps1 - launch vuln-shop (Node app on 3002) + Python Flask email-service (5002).

$ErrorActionPreference = 'Stop'
$AppRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $AppRoot

function Test-Command($name) {
    return $null -ne (Get-Command $name -ErrorAction SilentlyContinue)
}

# --- Node ---
if (-not (Test-Command 'node')) {
    Write-Host '[run.ps1] Node.js missing.' -ForegroundColor Yellow
    if (Test-Command 'winget') {
        $ans = Read-Host '[run.ps1] Install Node.js LTS via winget? [Y/n]'
        if ($ans -eq '' -or $ans -match '^[Yy]') {
            winget install --id OpenJS.NodeJS.LTS -e --accept-source-agreements --accept-package-agreements
        } else { exit 1 }
    } else { Write-Host 'Install Node.js manually.' ; exit 1 }
    $env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
}

# --- Python ---
$pythonCmd = $null
foreach ($c in 'python','py') {
    if (Test-Command $c) { $pythonCmd = $c; break }
}
if (-not $pythonCmd) {
    Write-Host '[run.ps1] Python missing.' -ForegroundColor Yellow
    if (Test-Command 'winget') {
        $ans = Read-Host '[run.ps1] Install Python 3 via winget? [Y/n]'
        if ($ans -eq '' -or $ans -match '^[Yy]') {
            winget install --id Python.Python.3.12 -e --accept-source-agreements --accept-package-agreements
        } else { exit 1 }
    } else { Write-Host 'Install Python 3 manually.' ; exit 1 }
    $env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
    foreach ($c in 'python','py') { if (Test-Command $c) { $pythonCmd = $c; break } }
}

Write-Host '[run.ps1] Node:'   (node --version)
Write-Host '[run.ps1] Python:' (& $pythonCmd --version)

# --- Install Node deps ---
if (-not (Test-Path (Join-Path $AppRoot 'node_modules'))) {
    Write-Host '[run.ps1] npm install...' -ForegroundColor Cyan
    npm install --no-fund --no-audit
}

# --- Install Flask via pip ---
$venv = Join-Path $AppRoot 'email-service\.venv'
if (-not (Test-Path $venv)) {
    Write-Host '[run.ps1] Creating Python venv for email-service...' -ForegroundColor Cyan
    & $pythonCmd -m venv $venv
}
$venvPython = Join-Path $venv 'Scripts\python.exe'
if (-not (Test-Path $venvPython)) { $venvPython = Join-Path $venv 'bin\python' }
Write-Host '[run.ps1] Installing Flask...' -ForegroundColor Cyan
& $venvPython -m pip install --quiet --upgrade pip
& $venvPython -m pip install --quiet -r (Join-Path $AppRoot 'email-service\requirements.txt')

$env:PORT = if ($env:PORT) { $env:PORT } else { '3002' }
$env:HOST = if ($env:HOST) { $env:HOST } else { '0.0.0.0' }
$env:EMAIL_SERVICE_URL = 'http://127.0.0.1:5002'

# Launch email service in background
Write-Host '[run.ps1] starting email-service on :5002 (background)...' -ForegroundColor Cyan
$emailLog = Join-Path $AppRoot 'email-service\email-service.log'
$emailProc = Start-Process -FilePath $venvPython `
  -ArgumentList (Join-Path $AppRoot 'email-service\email_service.py') `
  -WorkingDirectory (Join-Path $AppRoot 'email-service') `
  -RedirectStandardOutput $emailLog `
  -RedirectStandardError ($emailLog + '.err') `
  -PassThru -WindowStyle Hidden

Write-Host ''
Write-Host '===================================================' -ForegroundColor Green
Write-Host '  vuln-shop starting on http://localhost:3002' -ForegroundColor Green
Write-Host '  Storefront: http://localhost:3002/products' -ForegroundColor Green
Write-Host '  Login:      olivia.park / OliviaP!23' -ForegroundColor Green
Write-Host '  Admin:      admin_kate / AdminKate!1' -ForegroundColor Green
Write-Host '  Email svc:  http://localhost:5002/render (PID ' $emailProc.Id ')' -ForegroundColor Green
Write-Host '  See VULNERABILITIES.txt for exploit recipes.' -ForegroundColor Green
Write-Host '===================================================' -ForegroundColor Green
Write-Host ''

try {
    node server.js
} finally {
    Write-Host '[run.ps1] stopping email-service...'
    if ($emailProc -and -not $emailProc.HasExited) { Stop-Process -Id $emailProc.Id -Force -ErrorAction SilentlyContinue }
}
