# PowerShell script to check and add registry values, notify user, then restart

# Function to check and add registry value
function Add-RegistryValue 
{
    param (
        [string]$Path,
        [string]$Name,
        [int]$Value
    )
    
    if (-not (Test-Path $Path)) 
    {
        New-Item -Path $Path -Force
    }
    
    $currentValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $currentValue) 
    {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord
        return $true
    }
    return $false
}

# Paths and values
$paths = @(
    "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config",
    "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config"
)
$name = "EnableCertPaddingCheck"
$value = 1

# Check and add registry values
$restartNeeded = $false
foreach ($path in $paths) 
{
    if (Add-RegistryValue -Path $path -Name $name -Value $value) 
    {
        $restartNeeded = $true
    }
}

# Notify user and restart if any value was added
if ($restartNeeded) 
{
    # Create notification
    $message = "The computer will restart in 60 seconds to apply changes."
    $title = "Restart Notification"
    $toastXML = @"
<toast>
    <visual>
        <binding template='ToastGeneric'>
            <text>$title</text>
            <text>$message</text>
        </binding>
    </visual>
</toast>
"@

    $xmlDoc = New-Object Windows.Data.Xml.Dom.XmlDocument
    $xmlDoc.LoadXml($toastXML)

    $toast = [Windows.UI.Notifications.ToastNotification]::new($xmlDoc)
    $toastNotifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("PowerShell")
    $toastNotifier.Show($toast)

    # Wait for 60 seconds
    Start-Sleep -Seconds 60

    # Force restart
    Restart-Computer -Force
}
