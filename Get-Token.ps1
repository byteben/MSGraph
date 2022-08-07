<#
.SYNOPSIS
    This script can be used to obtain an authnetication token

.DESCRIPTION
    This script will use the MSAL.PS PowerShell module to obtain an authentication token and create an authorization header which can be used when scripting with Microsoft Graph 

.NOTES

    FileName:    Get-Token.ps1
    Author:      Ben Whitmore
    Contact:     @byteben
    Date:        7th August 2022

.PARAMETER TenantName
Specify the tenant name to connect to e.g bytebenlab.com

.PARAMETER Scope
Specify the scope to install the MSAL.PS module if it is missing. Valid Scopes are "CurrentUser" and "AllUsers"

.PARAMETER Context
Specify whether the token should be obtained interactively or with a device code. Valid contexts are "Interactive" and "DeviceCode"

.EXAMPLE
Get-Token.ps1 -TenantName 'bytebenlab.com' -Context 'Interactive' -Scope 'CurrentUser'

#>
[cmdletbinding()]
Param (
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [String]$TenantName,
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [ValidateSet('CurrentUser', 'AllUsers')]
    [String]$Scope,
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [ValidateSet('DeviceCode', 'Interactive')]
    [String]$Context

)
Function Get-ReqModule {
    Param (
        [Parameter(Mandatory)]
        [String]$ModuleName,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('CurrentUser', 'AllUsers')]
        [String]$Scope,
        [Parameter()]
        [Switch]$Install
    )

    #Check if module is installed
    $ModuleStatus = Get-Module -Name $ModuleName

    If (-not($ModuleStatus)) {
        Write-Verbose "$($ModuleName) is not currently installed"

        If ($Install) {

            #Install module
            Write-Verbose "Installing $($Module)"
            Try {
                Install-Module -Name $ModuleName -Scope $Scope
            }
            Catch {
                Write-Verbose "Error installing $($ModuleName)"
                $_
                break
            }
        }
    }
    else {
        Write-Verbose "$($ModuleName) is installed"
    }
}

#Set Application to use
$Module = "MSAL.PS"
$ClientID = '14d82eec-204b-4c2f-b7e8-296a70dab67e' #Microsoft Graph PowerShell Application ID

#Set Verbose Level
$VerbosePreference = "Continue"
#$VerbosePreference = "SilentlyContinue"

#Check required modules are installed, if not install them
Get-ReqModule -ModuleName $Module -Scope $Scope -Install

#Build auth params
$AuthParams = @{
    ClientId = $ClientID
    TenantId = $TenantName
    $Context = $true
}

#Get a Token
$AuthToken = Get-MsalToken @AuthParams

#Create HTTP basic auth header i.e base64-encoded username/password
$BasicAuthHeader = @{Authorization = $AuthToken.CreateAuthorizationHeader()}

#Disaply auth Header
$BasicAuthHeader 