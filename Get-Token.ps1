<#
.SYNOPSIS
    This script can be used to obtain an authnetication token

.DESCRIPTION
    This script will use the MSAL.PS PowerShell module to obtain an authentication token which can be used when scripting with Microsoft Graph 

.NOTES

    FileName:    Get-Token.ps1
    Author:      Ben Whitmore
    Contact:     @byteben
    Date:        7th August 2022

.PARAMETER TenantName
Specify the tenant name to connect to e.g bytebenlab.com

.PARAMETER Context
Specify whether the token should be obtained interactively or with a device code. Valid contexts are "Interactive" and "DeviceCode"

.PARAMETER ClientID
Specify the Azure app registration to use

.EXAMPLE
Get-Token.ps1 -TenantName 'bytebenlab.com' -Context 'Interactive' -Scope 'CurrentUser' -ClientID '9a5663eb-7dd3-41c6-80a2-70ba3e7cfbdf'

#>
[cmdletbinding()]
Param (
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [String]$TenantName = "",
    [String]$ClientID = "", #Replace with the CLientID from your Azure app registration
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [ValidateSet('DeviceCode', 'Interactive')]
    [String]$Context = "Interactive",
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [ValidateSet('CurrentUser', 'AllUsers')]
    [String]$Scope = "CurrentUser"

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

#Display Access Token to be used for Graph API requests
$AuthToken.AccessToken