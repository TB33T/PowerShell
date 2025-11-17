#script to use CSV of user SamAccountNames to get their group memberships & export to CSV
Import-Module ActiveDirectory

$CSV = Import-Csv -Path C:\samAccountNames.csv

Foreach ($account in $CSV)
{
    $user = $account.samaccountname
    $UN = Get-ADUser -identity $user -Properties memberof 
    $Groups = Foreach ($Group in $UN.MemberOf)
    {
        (Get-ADGroup $Group).Name
    }
    $Groups = $Groups | Sort
    Foreach ($Group in $Groups)
    {
        New-Object PSObject -Property @{
            Name = $UN.Name
            Group = $Group
        } | Export-Csv -Path C:\GroupMemberships.csv -NoTypeInformation -Append
    }
}
Write-Host "Group Memberships have been exported to a CSV file!" -ForegroundColor Magenta
