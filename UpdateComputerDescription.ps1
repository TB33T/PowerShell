#script to update computer description field

Import-Module ActiveDirectory

#enter computername
$comp = Read-Host -Prompt 'Enter Computer Name'

#enter description
$desc = Read-Host -Prompt 'Enter new Description'

Write-Host "The computer is $comp" -ForegroundColor Yellow
Write-Host "This will be the new description: $desc" -ForegroundColor Magenta

#sets new description
Set-ADComputer $comp -Description $desc

Write-Host "Description for $comp in AD has been updated to $desc" -ForegroundColor Green
