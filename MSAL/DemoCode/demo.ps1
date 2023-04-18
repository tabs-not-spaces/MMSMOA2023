#region Certificates
$subjectName = "AzureCertIntuneTesting"
$certStore = "LocalMachine"
$validityPeriod = 24

$newCert = @{
    Subject           = "CN=$($subjectName)"
    CertStoreLocation = "Cert:\$($certStore)\My"
    KeyExportPolicy   = "Exportable"
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
#endregion