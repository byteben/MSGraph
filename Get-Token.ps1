$tenantId = ""
$clientId = ""
$redirectUri = "http://localhost:8080"
$scope = "User.Read" 

# Start local HTTP listener
$http = [System.Net.HttpListener]::new()
$http.Prefixes.Add($redirectUri + "/")
Write-Host "Starting HTTP listener..."
$http.Start()
Write-Host "HTTP listener started and listening..."

# Construct the authorization URL
$authUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/authorize" `
    + "?client_id=$clientId" `
    + "&response_type=code" `
    + "&redirect_uri=$redirectUri" `
    + "&scope=$scope"

Write-Host "Opening authentication URL..."
Start-Process $authUrl

# Wait for the authorization response
$context = $http.GetContext()
$request = $context.Request
$response = $context.Response

# Extract the authorization code from the query string
$code = $request.QueryString["code"]

# Send a response to the browser
$buffer = [System.Text.Encoding]::UTF8.GetBytes("Authentication complete cheese man! You can close this window.")
$response.ContentLength64 = $buffer.Length
$response.OutputStream.Write($buffer, 0, $buffer.Length)
$response.OutputStream.Close()

# Exchange the code for an access token
$tokenUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
$body = @{
    client_id    = $clientId
    code         = $code
    redirect_uri = $redirectUri
    grant_type   = "authorization_code"
    scope        = $scope
}

$token = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body

# Clean up
$http.Stop()
$http.Close()

Write-Host "Access Token: $($token.access_token)"