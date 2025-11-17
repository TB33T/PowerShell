#script for copying user profile data from old computer to new computer
$oldcomputer = Read-Host -Prompt 'Enter name of Old computer'
$newcomputer = Read-Host -Prompt 'Enter name of New computer'
$user = Read-Host -Prompt 'Enter name of user account'
$profilefolder = Read-Host -Prompt 'Enter the profile folder to be copied'

Write-Host "Old computer is $oldcomputer" -ForegroundColor Green
Write-Host "New computer is $newcomputer" -ForegroundColor Yellow
Write-Host "User Account is $user" -ForegroundColor Green
Write-Host "The folder to be copied is $profilefolder" -ForegroundColor Yellow

Copy-Item \\$oldcomputer\c$\Users\$user\$profilefolder\* -Destination \\$newcomputer\c$\Users\$user\$profilefolder -Recurse
Write-Host "Folder $profilefolder has been copied!" -ForegroundColor Green

#loop for copying more user folders
do 
{ 
$UserInput = Read-Host -Prompt 'Do you want to copy another profile folder? (Y)es or (N)o'
If ($UserInput -ne 'y')
	{
	 Write-Host "The end is near!"  -ForegroundColor Yellow
	}
Else 
	{
	 $profilefolder = Read-Host -Prompt 'Enter the profile folder to be copied'
     Copy-Item \\$oldcomputer\c$\Users\$user\$profilefolder\* -Destination \\$newcomputer\c$\Users\$user\$profilefolder -Recurse
     Write-Host "Folder $profilefolder has been copied!" -ForegroundColor Green
	}
}
until ($UserInput -eq 'n')

#end of copying script
Write-Host "$user profile copying is complete!" -ForegroundColor Green
