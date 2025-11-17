#script to add bulk list of employees to Teams channel via CSV file
Connect-MicrosoftTeams

$CSV = Import-csv -path C:\EmailAddress.csv

$count = 0
$count2 = $CSV.Count
Write-host "total users is $count2"

#get GroupID by using Get-Team -user $emailUsername for someone on the Team
$Team = Read-Host -Prompt "Please input GroupID"
$Display = $Team.DisplayName

foreach($account in $CSV)
{   
    $user = $account.email
    Add-TeamUser -GroupID $Team -user $user
    Write-host "Adding $user to $Display" -ForegroundColor Magenta

    $count++
    Write-Progress -Activity "Script is running" -status "Adding members to Team..." -percentComplete ($count / $count2 *100)
}
Write-Host "All accounts added to Teams Channel" -ForegroundColor Green
