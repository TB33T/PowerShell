#creates registry for autologon for local account

$username = "username"
$password = "password"
$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$hostname = hostname

#create and set autologin in registry
New-ItemProperty $RegPath "AutoAdminLogon" -Value "1" -type String
New-ItemProperty $RegPath "DefaultUsername" -Value "$username" -type String
New-ItemProperty $RegPath "DefaultPassword" -Value "$password" -type String
New-ItemProperty $RegPath "DefaultDomainName" -Value "$hostname" -type String
#set local display account password to never expire
Set-LocalUser -Name "$username" -PasswordNeverExpires $true
Exit 0
