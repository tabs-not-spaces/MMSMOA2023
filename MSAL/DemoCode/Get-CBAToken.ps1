<#
.SYNOPSIS
    Authenicate using an Azure application and a certificate to obtain a token
.DESCRIPTION
    After generating a self signed certificate, use the pfx to authenticate to AzureAD to obtain a token
.EXAMPLE
    Get-CBAToken.ps1 -tenantId "0cebf1f4-e0c4-46d4-8c5a-0fc80bed6b2c" -applicationId "47727b19-7b3f-472a-8057-704affed1815" -pfxFile "C:\temp\certs\AzureCertIntuneTesting.pfx" -pfxPassword "123"
.NOTES
    
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$pfxFile,
    [string]$tenantId,
    [string]$applicationId,
    [string]$pfxPassword
)

$Scope = "https://graph.microsoft.com/.default"

If (-not $pfxPassword) {
    $pfxPassword = Read-Host -Prompt "Enter password for your certificate: " -AsSecureString
}
else {
    $pfxPassword = ConvertTo-SecureString -String $pfxPassword -AsPlainText -Force
}

#get certificate hash and create base64 string
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$cert.Import($pfxFile, $certPassword, 'DefaultKeySet')
$cert64Hash = [System.Convert]::ToBase64String($cert.GetCertHash())  

function Get-Token {
    #create JWT timestamp for expiration 
    $startDate = (Get-Date "1970-01-01T00:00:00Z" ).ToUniversalTime()  
    $jwtExpireTimeSpan = (New-TimeSpan -Start $startDate -End (Get-Date).ToUniversalTime().AddMinutes(2)).TotalSeconds  
    $jwtExpiration = [math]::Round($jwtExpireTimeSpan, 0)  
  
    #create JWT validity start timestamp  
    $notBeforeExpireTimeSpan = (New-TimeSpan -Start $StartDate -End ((Get-Date).ToUniversalTime())).TotalSeconds  
    $notBefore = [math]::Round($notBeforeExpireTimeSpan, 0)  
  
    #create JWT header  
    $jwtHeader = @{  
        alg = "RS256"  
        typ = "JWT"  
        x5t = $cert64Hash -replace '\+', '-' -replace '/', '_' -replace '='  
    }  
  
    #create JWT payload  
    $jwtPayLoad = @{  
        aud = "https://login.microsoftonline.com/$tenantId/oauth2/token"  
        exp = $jwtExpiration   
        iss = $applicationId  
        jti = [guid]::NewGuid()   
        nbf = $notBefore  
        sub = $applicationId  
    }  
  
    #convert header and payload to base64  
    $jwtHeaderToByte = [System.Text.Encoding]::UTF8.GetBytes(($jwtHeader | ConvertTo-Json))  
    $encodedHeader = [System.Convert]::ToBase64String($jwtHeaderToByte)  
  
    $jwtPayLoadToByte = [System.Text.Encoding]::UTF8.GetBytes(($jwtPayLoad | ConvertTo-Json))  
    $encodedPayload = [System.Convert]::ToBase64String($jwtPayLoadToByte)  
  
    #join header and Payload with "." to create a valid (unsigned) JWT  
    $jwt = $encodedHeader + "." + $encodedPayload  
  
    #get the private key object of your certificate  
    $privateKey = ([System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAprivateKey($cert))  
  
    #define RSA signature and hashing algorithm  
    $rsaPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1  
    $hashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256  
  
    #create a signature of the JWT  
    $signature = [Convert]::ToBase64String(  
        $privateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($jwt), $hashAlgorithm, $rsaPadding)  
    ) -replace '\+', '-' -replace '/', '_' -replace '='  
  
    #join the signature to the JWT with "."  
    $jwt = $jwt + "." + $signature  
  
    #create a hash with body parameters  
    $body = @{  
        client_id             = $applicationId  
        client_assertion      = $jwt  
        client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"  
        scope                 = $scope  
        grant_type            = "client_credentials"  
  
    }  
  
    $url = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"  
  
    #use the self-generated JWT as Authorization  
    $header = @{  
        Authorization = "Bearer $jwt"  
    }  
  
    #splat the parameters for Invoke-Restmethod for cleaner code  
    $postSplat = @{  
        ContentType = 'application/x-www-form-urlencoded'  
        Method      = 'POST'  
        Body        = $body  
        Uri         = $url  
        Headers     = $header  
    }  
  
    $request = Invoke-RestMethod @postSplat  

    #view access_token  
    $request
}

Get-Token -tenantId $tenantId -applicationId $applicationId -scope $scope -cert $cert -certBase64Hash $cert64Hash