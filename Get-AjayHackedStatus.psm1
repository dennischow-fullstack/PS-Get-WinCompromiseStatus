<#
Created this API with PowerShell v5
because everyone could use an Ajay Safe Space

In honor of the SVTX StartUpBus 2018's
conductor: Ajay Desai 

Provides indicators of compromise
for windows hosts if you're likely
to be "hacked" based on suspicious
use cases. Outputs to JSON. 
Quick and dirty, no warranties.

Disclaimer: The basic use cases are just that
make sure to layer this with other solutions

Provide a computer name or IP address
Requires end host to have WinRM enabled
You can do it with WMI or CIM but I'm lazy.
Or just insert this into a local script.

Also note: This only finds low hanging
fruit in user space portion of the OS.

Usage: 
Import-Module AjayAPI.psm1
Get-AjayHackedStatus -host "hostname.local"


By: Dennis Chow
dchow[AT]xtecsystems.com
#>
function Get-AjayHackedStatus {
	param( [string]$host )

	#get all processes less than 1MB
	Invoke-Command -ComputerName $host -ScriptBlock { Get-Process | Where-Object { $_.WorkingSet -lt 1024000 } | ConvertTo-Json }

    #show all lower ports listening thats not 445 tcp
	Invoke-Command -ComputerName $host -ScriptBlock { Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" -and $_.LocalPort -lt 1024 -and $_.LocalPort -ne 445 } | ConvertTo-Json }

    #show profiles where host fw is disabled
    Invoke-Command -ComputerName $host -ScriptBlock { Get-NetFirewallProfile | Select-Object Enabled,Name,LogFileName | Where-Object { $_.Enabled -ne "True" } | ConvertTo-Json }

    #Show unsigned drivers installed
    Invoke-Command -ComputerName $host -ScriptBlock { driverquery.exe /SI | Select-String -CaseSensitive "FALSE" | ConvertTo-Json }

    #Shows uncommented portions of a Windows HOSTS file
    Invoke-Command -ComputerName $host -ScriptBlock { Get-Content ("$env:SystemRoot\system32\drivers\etc\hosts") | Select-String -NotMatch "#" | ConvertTo-Json }

    #Show items to be ran on startup. Note includes all files. 
    Invoke-Command -ComputerName $host -ScriptBlock { Get-CimInstance Win32_StartupCommand | ConvertTo-Json }

}