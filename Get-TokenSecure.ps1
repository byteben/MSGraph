[CmdletBinding(SupportsShouldProcess)]
param (
    [string]$TenantId = "",
    [string]$ClientId = "",
    [string]$Scope = "User.Read",
    [int]$MinimumValiditySeconds = 300
)

function Get-AvailablePort {
    $tcpListener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    try {
        $tcpListener.Start()
        $port = ([System.Net.IPEndPoint]$tcpListener.LocalEndpoint).Port
        return $port
    }
    finally {
        $tcpListener.Stop()
    }
}

function Get-RedirectUri {
    $port = Get-AvailablePort
    return "http://localhost:$port"
}

function Generate-PKCE {
    $codeVerifier = -join ((65..90) + (97..122) | Get-Random -Count 128 | % { [char]$_ })
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($codeVerifier)
    $codeChallenge = [System.Convert]::ToBase64String($sha256.ComputeHash($bytes)) -replace '\+', '-' -replace '/', '_' -replace '='
    return @{ Verifier = $codeVerifier; Challenge = $codeChallenge }
}

function Get-AuthorizationCode {
    param (
        [string]$TenantId,
        [string]$ClientId,
        [string]$RedirectUri,
        [string]$CodeChallenge,
        [string]$Scope
    )

    $http = [System.Net.HttpListener]::new()
    $http.Prefixes.Add("$RedirectUri/")
    $http.Start()

    $state = -join ((65..90) + (97..122) | Get-Random -Count 32 | % {[char]$_})
    $encodedState = [System.Web.HttpUtility]::UrlEncode($state)

    $authUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize" `
        + "?client_id=$ClientId" `
        + "&response_type=code" `
        + "&redirect_uri=$RedirectUri" `
        + "&scope=$Scope" `
        + "&code_challenge=$CodeChallenge" `
        + "&code_challenge_method=S256" `
        + "&state=$encodedState"

    Write-Host "Opening authentication page..."
    Start-Process $authUrl

    $context = $http.GetContext()
    $receivedState = $context.Request.QueryString["state"]
    if ($receivedState -ne $encodedState) {
        throw "State parameter mismatch"
    }

    $code = $context.Request.QueryString["code"]
    Send-ResponseHtml -Response $context.Response

    $http.Stop()
    return $code
}

function Send-ResponseHtml {
    param ([System.Net.HttpListenerResponse]$Response)

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Authentication Complete</title>
    <style>
        body { font-family: "Segoe UI", sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: #f0f2f5; }
        .container { background-color: white; padding: 40px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); text-align: center; }
        h1 { margin-bottom: 16px; font-size: 28px; }
        p { font-size: 18px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Authentication Complete</h1>
        <p>You can close this window now, Cheese Man.</p>
    </div>
    <script>window.onload = function() { history.replaceState({}, document.title, '/'); }</script>
</body>
</html>
"@

    $buffer = [System.Text.Encoding]::UTF8.GetBytes($html)
    $Response.ContentType = "text/html"
    $Response.ContentLength64 = $buffer.Length
    $Response.StatusCode = 200
    $Response.StatusDescription = "OK"
    $Response.OutputStream.Write($buffer, 0, $buffer.Length)
    $Response.OutputStream.Flush()
    $Response.Close()
}

function Exchange-AuthCodeForToken {
    param (
        [string]$TenantId,
        [string]$ClientId,
        [string]$RedirectUri,
        [string]$Code,
        [string]$CodeVerifier,
        [string]$Scope
    )

    Write-Verbose "Exchange-AuthCodeForToken called with:"
    Write-Verbose "Code: $Code"
    Write-Verbose "CodeVerifier: $CodeVerifier"
    Write-Verbose "RedirectUri: $RedirectUri"

    $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $body = @{
        client_id     = $ClientId
        code          = $Code
        code_verifier = $CodeVerifier
        redirect_uri  = $RedirectUri
        grant_type    = "authorization_code"
        scope         = $Scope
    }

    Write-Verbose "Request body:"
    Write-Verbose ($body | ConvertTo-Json)

    # Add content type explicitly
    $token = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
    return @{
        AccessToken = $token.access_token
        ExpiresAt   = (Get-Date).AddSeconds($token.expires_in)
        TokenType   = $token.token_type
        Scope       = $token.scope
    }
}

function Get-AccessToken {
    param (
        [string]$TenantId,
        [string]$ClientId,
        [string]$Scope,
        [datetime]$TokenExpiry = [DateTime]::MinValue,
        [int]$MinimumValiditySeconds
    )

    Write-Verbose ("Current time is: {0}" -f (Get-Date))
    Write-Verbose ("Token expiry time is: {0}" -f $TokenExpiry)
    Write-Verbose ("Minimum validity seconds required: {0}" -f $MinimumValiditySeconds)

    $minimumValidUntil = (Get-Date).AddSeconds($MinimumValiditySeconds)
    Write-Verbose ("Token must be valid until: {0}" -f $minimumValidUntil)
    
    if ($TokenData -and $TokenExpiry -gt $minimumValidUntil) {
        $timeUntilExpiry = ($TokenExpiry - (Get-Date)).ToString("hh\:mm\:ss")
        Write-Verbose ("Using existing valid access token. Token expires in: {0}" -f $timeUntilExpiry)
        return $TokenData
    }

    Write-Verbose ("Token validation failed because expiry time {0} is not after minimum valid until time {1}" -f $TokenExpiry, $minimumValidUntil)
    Write-Verbose "Starting authentication for new token..."

    $RedirectUri = Get-RedirectUri
    $PKCE = Generate-PKCE
    $Code = Get-AuthorizationCode -TenantId $TenantId -ClientId $ClientId -RedirectUri $RedirectUri -CodeChallenge $PKCE.Challenge -Scope $Scope
    return Exchange-AuthCodeForToken -TenantId $TenantId -ClientId $ClientId -RedirectUri $RedirectUri -Code $Code -CodeVerifier $PKCE.Verifier -Scope $Scope
}

# Main execution flow
$minimumValidUntil = (Get-Date).AddSeconds($MinimumValiditySeconds)

Write-Verbose ("Current time is: {0}" -f (Get-Date))
Write-Verbose ("TokenData exists: {0}" -f ($null -ne $TokenData))
Write-Verbose "Checking if existing token is valid..."

if ($TokenData -and $TokenData.ExpiresAt -gt $minimumValidUntil) {
    $timeUntilExpiry = ($TokenData.ExpiresAt - (Get-Date)).ToString("hh\:mm\:ss")
    Write-Verbose ("Using existing valid access token. Token expires in: {0}" -f $timeUntilExpiry)
}
else {
    Write-Verbose "Token validation failed because:"
    if (-not $TokenData) {
        Write-Verbose "  - TokenData is null or empty"
    }
    elseif (-not ($TokenData.ExpiresAt -gt $minimumValidUntil)) {
        Write-Verbose ("  - Token expiry time ({0}) is not greater than minimum valid until time ({1})" -f $TokenData.ExpiresAt, $minimumValidUntil)
    }
    
    Write-Verbose "Getting new token..."
    $tokenExpiry = if ($TokenData) { $TokenData.ExpiresAt } else { [DateTime]::MinValue }
    
    $TokenData = Get-AccessToken -TenantId $TenantId -ClientId $ClientId -Scope $Scope `
        -TokenExpiry $tokenExpiry -MinimumValiditySeconds $MinimumValiditySeconds
}

Write-Verbose "`nAccess Token Details:"
Write-Verbose "Access Token: (Stored in memory as `$TokenData.AccessToken)"
Write-Verbose ("Expires At: {0}" -f $TokenData.ExpiresAt)
Write-Verbose ("Token Type: {0}" -f $TokenData.TokenType)
Write-Verbose ("Scope: {0}" -f $TokenData.Scope)