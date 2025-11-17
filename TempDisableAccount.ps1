#Script for temp disable accounts and move to Temporary-Disable OU
Import-Module ActiveDirectory

#this should be the samaccountname
$user = Read-Host -Prompt 'Enter the User account name'
Write-Host "The user is $user"  -ForegroundColor yellow

#Disables account & add description with ticket # to account
Disable-ADAccount -Identity $user
$ticket = Read-Host -Prompt "Enter the ticket #"
Set-ADUser -Identity $user -Description "Temp Disable - $ticket"

#moves account to Temp Disable OU, this should be the DistinguishedName of the path
$TempOU = "OU=Temporary OU"
Get-ADuser $user -Properties DistinguishedName | Move-ADObject -TargetPath $TempOU

Write-Host "$user has been moved to the TempDisable OU"  -ForegroundColor Green
