#This script will get local drives free space available.

get-wmiobject win32_volume | where-object {$_.capacity -gt 0} | sort-object Name | ft Name,@{label="Percentage Freespace";expression={($_.freespace/$_.capacity*100).tostring().substring(0,5)}} -auto
