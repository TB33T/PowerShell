#Script to add permissions for multiple users to a shared mailbox

$users = Import-Csv -Path C:\EmailAddress.csv

#use FQDN for credentials
$UserCredential = Get-Credential

#run to start O365 session
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $UserCredential -Authentication Basic -AllowRedirection

#this disables cmdlet name checking
Import-PSSession $Session -DisableNameChecking

#can use UPN, email address, or samaccountname
$box = Read-Host -Prompt 'Enter the name of the shared mailbox'

#the input should be "y", "Y", or "yes"
$access = Read-Host -Prompt 'Will employees need Send As permission?'

#this loop will add FullAccess rights for all users in the CSV. If $access input was "yes", they #will also receive SendAs permissions

foreach ($user in $users)
{
    $account = $user.email

    Add-MailboxPermission -Identity "$box" -User $account -AccessRights FullAccess -InheritanceType all -confirm:$false
    if ($access -like 'y' -or $access -like 'Y' -or $access -like 'yes')
    {
        Add-RecipientPermission -Identity "$box" -Trustee $account -AccessRights SendAs -confirm: $false
    }
    else
    {
        Write-Host "Send As permissions are NOT assigned" -ForegroundColor Magenta
    }
}

Remove-PSSession $Session
Write-Host "Delegated mailbox permissions have been assigned for $box"
