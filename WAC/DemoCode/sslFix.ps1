#region Get thumbprint for a new certificate

Get-ChildItem cert:\LocalMachine\my
#write down the thumbprint

#endregion

#region Show config:

netsh http show sslcert
#Write down "Application ID"

#endregion

#region Delete existing config:

netsh http delete sslcert ipport=0.0.0.0:443

#endregion

#region bind new cert:

netsh http add sslcert ipport=0.0.0.0:443 certhash="SSLThumbprint" appid="{Application ID}"

#endregion

#region Restart "Windows Admin Center" service

Get-Service -Name "ServerManagementGateway" | Restart-Service -Force

#endregion