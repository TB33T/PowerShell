#script to disable IPv6 across all network adapters
Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
Exit 0