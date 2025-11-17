$list = "C:\computers.txt" 
$report = "C:\local-users.csv" 
$computers = Get-Content -Path $list 

Get-WmiObject -ComputerName $computers -Class Win32_UserAccount -Filter "LocalAccount='True'" | Select PSComputername, Name, Status, Disabled, AccountType, Lockout, PasswordRequired, PasswordChangeable, SID | Export-csv $report -NoTypeInformation
