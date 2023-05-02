#region auth config
. ./MSAL/DemoCode/local.ps1
#endregion

$requestBody = @{
    resource   = 'https://graph.microsoft.com'
    client_id  = $env:appId
    grant_type = "password"
    username   = $env:usrEmail
    scope      = "openid"
    password   = $env:passwd
}
$auth = Invoke-RestMethod -Method post -Uri "https://login.microsoftonline.com/$($env:tenant)/oauth2/token" -Body $requestBody
$auth
test