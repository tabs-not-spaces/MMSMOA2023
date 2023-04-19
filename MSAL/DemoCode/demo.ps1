#region certificates
$subjectName = "AzureCertIntuneTesting"
$certStore = "LocalMachine"
$validityPeriod = 24

$newCert = @{
    Subject           = "CN=$($subjectName)"
    CertStoreLocation = "Cert:\$($certStore)\My"
    KeyExportPolicy   = "Exportable"    #Exportable not great security practice tbh, use NonExportable
    KeySpec           = "Signature"
    NotAfter          = (Get-Date).AddMonths($($validityPeriod))
}
$Cert = New-SelfSignedCertificate @newCert

#export public key only
$certFolder = "C:\temp\certs"
$certExport = @{
    Cert     = $Cert
    FilePath = "$($certFolder)\$($subjectName).cer"
}
Export-Certificate @certExport

#export with private key
$certFolder = "C:\temp\certs"
$certThumbprint = $Cert.Thumbprint
$certPassword = Read-Host -Prompt "Enter password for your certificate: " -AsSecureString
$pfxExport = @{
    Cert         = "Cert:\$($certStore)\My\$($certThumbprint)"
    FilePath     = "$($certFolder)\$($subjectName).pfx"
    ChainOption  = "EndEntityCertOnly"
    NoProperties = $null
    Password     = $certPassword
}
Export-PfxCertificate @pfxExport

#connect to service principal with MSAL using certificate for authentication. Requires the private key to be marked as exportable and user has privilege to read the key (Admin?)
$clientID = "06daac75-f978-4039-b563-4278554067c6"
$tenantID = "0cebf1f4-e0c4-46d4-8c5a-0fc80bed6b2c"
$certThumbprint = "34ad11569e9d69b92a09f72f64791fd06beb2cc3"
$clientCertificate = Get-ChildItem "Cert:\$($certStore)\my\$($certThumbprint)"
$authToken = Get-MsalToken -clientID $clientID -tenantID $tenantID -clientCertificate $clientCertificate

#make a Graph call using the token to test it works
$resourceURI = "deviceAppManagement/mobileApps"
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
#endregion