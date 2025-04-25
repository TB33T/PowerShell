#adds local EITAdmin account to the local administrators group
Add-LocalGroupMember -Group "Administrators" -Member "Admin"

$admin = "Admin"

$localAdmin = (net localgroup Administrators | Select-String $admin -SimpleMatch).ToString()

#if Admin is in the local administrators group exits with code 0 (true)
if($localAdmin -eq $admin)
{
    Exit 0
}
else
{
    Exit 1
}
