#script to restore all items that were accidently deleted from a mailbox in Outlook

$UserCredential = Get-Credential

$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $UserCredential -Authentication Basic -AllowRedirection

Import-PSSession $Session -DisableNameChecking

#enter email address
$mailbox = Read-Host -prompt 'Enter an email address'

#finds all recoverable items
Get-Recoverableitems -identity $mailbox

#restores all recoverable items
Restore-RecoverableItems -identity $mailbox

Write-Host "All Recoverable Items have been Restored! You're welcome!" -ForegroundColor Green

Remove-PSSession $Session
