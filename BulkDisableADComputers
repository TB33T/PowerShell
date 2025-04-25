#Trevor.Brunner - 11/6/2024
#script to disable computers from CSV and append the date they were disabled

#Define the path to the CSV file
$csvPath = "C:\Users\trevor.brunner\Desktop\ComputersToDisable.csv"

#Import the CSV file
$computers = Import-Csv -Path $csvPath

#Get the current date
$currentDate = Get-Date -Format "MM/dd/yyyy"

$count = 0
$count2 = $computers.count
Write-Host "total computers is $count2" -ForegroundColor Yellow

#Loop through each computer in the CSV
foreach ($computer in $computers) 
{
    $computerName = $computer.Name

    #Disable the computer account
    Disable-ADAccount -Identity $computerName
    Write-Host "$computerName has been disabled" -ForegroundColor Magenta

    #Get the current description
    #$description = (Get-ADComputer -Identity $computerName -Properties Description).Description

    #Append the current date to the description
    $newDescription = "Disabled on $currentDate"

    #Update the description field
    Set-ADComputer -Identity $computerName -Description $newDescription

    $count++
    $percentComplete = ($count / $count2) *100
    Write-Progress -Activity "Script is running" -Status "Disabling computers..." -PercentComplete $percentComplete
}

Write-Host "Completed disabling computers and updating descriptions" -ForegroundColor Green
