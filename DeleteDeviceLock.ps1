#script to check registry for DeviceLock and delete if it exists
$path = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceLock"

#check if the path exists
if ((Get-Item -Path $path -ErrorAction Ignore) -ne $null) 
{
    #Remove the value
    Remove-Item -Path $path -ErrorAction Ignore -Recurse -Force
}