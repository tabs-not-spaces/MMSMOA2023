#region certificates
$subjectName = "AzureCertIntuneTesting999"
$certStore = "LocalMachine"
$validityPeriod = 24

$newCert = @{
    Subject           = "CN=$($subjectName)"
    CertStoreLocation = "Cert:\$($certStore)\My"
    KeyExportPolicy   = "NonExportable"    #Exportable not great security practice tbh, use NonExportable?
    KeySpec           = "Signature"
    NotAfter          = (Get-Date).AddMonths($($validityPeriod))
}
$cert = New-SelfSignedCertificate @newCert

#export public key only
$certFolder = "C:\temp\certs"
$certExport = @{
    Cert     = $cert
    FilePath = "$($certFolder)\$($subjectName).cer"
}
Export-Certificate @certExport

#export with private key
$certFolder = "C:\temp\certs"
$certPassword = Read-Host -Prompt "Enter password for your certificate: " -AsSecureString
$pfxExport = @{
    Cert         = "Cert:\$($certStore)\My\$($cert.Thumbprint)"
    FilePath     = "$($certFolder)\$($subjectName).pfx"
    ChainOption  = "EndEntityCertOnly"
    NoProperties = $null
    Password     = $certPassword
}
Export-PfxCertificate @pfxExport

#connect to service principal with MSAL using certificate for authentication. 
$clientID = "06daac75-f978-4039-b563-4278554067c6"
$tenantID = "0cebf1f4-e0c4-46d4-8c5a-0fc80bed6b2c"
$clientCertificate = Get-ChildItem "Cert:\$($certStore)\my\$($cert.Thumbprint)"
$authToken = Get-MsalToken -clientID $clientID -tenantID $tenantID -clientCertificate $clientCertificate

#make a Graph call using the token to test it works
$resourceURI = "deviceAppManagement/mobileApps?`$filter=(isof('microsoft.graph.win32LobApp'))"
$method = "GET"
$apiEndpoint = "beta"

$graphParams = @{
    Headers = @{
        "Content-Type"  = "application/json"
        "Authorization" = "$($authToken.AccessToken)"
    }
    Method  = $method
    URI     = "https://graph.microsoft.com/$($apiEndpoint)/$($resourceURI)"
}

(Invoke-RestMethod @graphParams).value

#alternative - use Microsoft.Graph module to connect using a certificate
Install-Module Microsoft.Graph -Force
Import-Module -Name Microsoft.Graph
Connect-MgGraph -TenantId $tenantID -ClientId $clientID -Certificate $clientCertificate
Get-mgContext

#Get-CBATokenMSAL.ps1 - putting it all together
#endregion