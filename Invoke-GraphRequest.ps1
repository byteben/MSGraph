###################
#Simple
####################

$token = Get-MsalToken -ClientId '' -TenantId 'bytebenlab.com' -Interactive
$authHeader = @{authorization = $token.CreateAuthorizationHeader() }

$uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?$filter=startswith(displayName,'Voltage') &$orderby=displayName"
$payload = Invoke-RestMethod -Method GET -Headers $authHeader -uri $uri


$image = "$($env:temp)\$($payload.displayName).png"
[byte[]]$Bytes = [convert]::FromBase64String(($payload.largeIcon.value))
[System.IO.File]::WriteAllBytes($image, $Bytes)
Start-Process $image

####################
#Get Token
####################

$AuthParams = @{
    ClientId    = "" 
    TenantId    = ""
    Interactive = $true
}
<#
####################
#Get Refresh Token
####################
$AuthParams = @{
    ClientId    = "9a5663eb-7dd3-41c6-80a2-70ba3e7cfbdf" #Bytebenlab App Registration
}
#>

$AuthToken = Get-MsalToken @AuthParams


####################
#Create Header
####################
Function ConvertTo-UrlEncodedString {
    [cmdletbinding()]
    param (
        [parameter(mandatory = $true)]
        [string]$AppName
    )
    #Double Encode String
    $EncodedString = [System.Web.HttpUtility]::UrlEncode($AppName)
    return $EncodedString
    
}
Function Create-GraphCall {
    Param (
        [Parameter()]
        [String]$ResourceURI,
        [String]$AppName,
        [String]$Method = "GET",
        [String]$APIEndpoint = "beta"
    )

    #URL Double Encode escaping characters
    If ($AppName) {
        $AppNameEncoded = ConvertTo-UrlEncodedString $AppName
        $ResourceURI = $ResourceURI.replace('$AppName', $AppNameEncoded)
    }

    $GraphParams = @{

        Headers = @{
            "Content-Type"  = "application/json"
            "Authorization" = "$($AuthToken.AccessToken)"
        }
        Method  = $Method
        URI     = "https://graph.microsoft.com/$($APIEndpoint)/$($ResourceURI)"
    }
    Return $GraphParams
}


####################
#Get All Win32apps
####################

$ResourceURI = "deviceAppManagement/mobileApps?`$filter=(isof('microsoft.graph.win32LobApp'))&`$orderby=displayName"

####################
#Get Win32apps
####################

$AppName = "Notepad++"
$ResourceURI = "deviceAppManagement/mobileApps?filter=(isof('microsoft.graph.win32LobApp'))&search=`"`$AppName`"&orderby=displayName"
#$ResourceURI = "deviceAppManagement/mobileApps?filter=(isof('microsoft.graph.win32LobApp')) and startswith(displayName,'`$AppName')&orderby=displayName"
$Resourceuri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?$filter=startswith(displayName,'Voltage') &$orderby=displayName"

####################
#Invoke-WebRequest
####################
$Payload = (Create-GraphCall -ResourceURI $ResourceURI)
Write-Verbose "Created URI: ($($Payload.Method)) $($Payload.URI)" -Verbose
$Result = (Invoke-RestMethod @Payload).Value
foreach ($App in $Result) { $App | Select-Object id, displayName, displayVersion } 