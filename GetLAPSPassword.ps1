#Script to get the local admin password for domain joined workstations using LAPS

Import-Module activedirectory

$computer = Read-Host "Enter computer name"
Write-Host "The computer is $computer" -ForegroundColor Yellow

#pulls attribute for local admin password
Get-ADComputer $computer -Properties name,ms-Mcs-AdmPwd | fT name,ms-Mcs-AdmPwd | Out-File "C:\LocalAdmPwd.csv" -Append

Write-Host "The local admin password has been exported to a CSV" -ForegroundColor green
