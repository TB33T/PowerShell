#Script to check if the Automox Agent(amagent) service is running
#If Exit 1 runs the Remediation script will be run
# Detection Script

# Replace "YourServiceName" with the actual service name
$ServiceName = "amagent"

$Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

if($Service -eq $null) 
{
    Write-Host "Service '$ServiceName' not found."
    exit 1 # Not found, therefore not compliant.
}

if($Service.Status -ne "Running") 
{
    Write-Host "Service '$ServiceName' is not running."
    exit 1 # Not running, therefore not compliant. Will run the remediation script.
} 
else 
{
    Write-Host "Service '$ServiceName' is running."
    exit 0 # Running, therefore compliant.
}