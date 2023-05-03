$params = @{
    ClientId = ""
    TenantId = ""
    Interactive = $true
}
$token = Get-MsalToken @params