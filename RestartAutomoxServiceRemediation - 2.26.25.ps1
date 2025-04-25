#Script to start the Automox Agent(amagent) service

# Remediation Script

# Replace "YourServiceName" with the actual service name
$ServiceName = "amagent"

# Check if the service is running
$Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

if($Service -eq $null) 
{
    Write-Warning "Service '$ServiceName' not found."
    exit 1 # Indicate failure
}

if($Service.Status -ne "Running") 
{
    try 
    {
        Start-Service -Name $ServiceName -ErrorAction Stop
        Write-Host "Service '$ServiceName' started successfully."
        exit 0 # Indicate success
    }
    catch 
    {
        Write-Error "Failed to start service '$ServiceName': $($_.Exception.Message)"
        exit 2 # Indicate failure
    }
} 
else 
{
    Write-Host "Service '$ServiceName' is already running."
    exit 0 # Indicate success
}