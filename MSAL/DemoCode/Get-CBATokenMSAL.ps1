<#
.SYNOPSIS
    Authenicate using an Azure application and a certificate to obtain a token
.DESCRIPTION
    After generating a self signed certificate, use the MSAL.PS module to authenticate to AzureAD to obtain a token
.EXAMPLE
    .\Get-CBATokenMSAL.ps1 -tenantId "0cebf1f4-e0c4-46d4-8c5a-0fc80bed6b2c" -applicationId "47727b19-7b3f-472a-8057-704affed1815" -certStore "CurrentUser" -thumbprint "1dba6cef466908426ca5985f9f4473892b2d5cbb"
.NOTES
    Requires MSAL.PS module // Install-Module MSAL.PS -Scope CurrentUser    
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidateSet('LocalMachine', 'CurrentUser')]
    [string]$certStore = "LocalMachine",
    [string]$thumbprint = "C524D85CF46EE498B58F3874DE947A7F06A718AB",
    [string]$tenantId = "0cebf1f4-e0c4-46d4-8c5a-0fc80bed6b2c",
    [string]$applicationId = "06daac75-f978-4039-b563-4278554067c6"
)
Function Get-Token {
    #connect to graph and authenticate with the certificate
    Import-Module -Name MSAL.PS -Force

    $connectStringSplat = @{
        TenantId          = $tenantId
        ClientId          = $applicationId
        ClientCertificate = Get-Item -Path "Cert:\$($certStore)\My\$($thumbprint)"
    }

    $tokenRequest = Get-MsalToken @connectStringSplat
    Return $tokenRequest
}

#get token
$authToken = (Get-Token).AccessToken

#test token
Invoke-RestMethod -Headers @{"Authorization" = "$($AuthToken)"}-Method GET -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?$filter=(isof('microsoft.graph.win32LobApp'))"