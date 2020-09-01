$cred= Get-Credential
[array]$all_hosts = "Host-01","Host-02","Host-03","Host-04","Host-05"
$log_path = "C:\host-audit-20200901-allhosts.csv"
[datetime]$StartTime = "May 1, 2020"

$script_block= {
    param($StartTime)
    $Servers = (hostname)

    foreach ($Server in $Servers) {

        $LogFilter = @{
            LogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
            ID = 21, 23, 24, 25
            StartTime = $StartTime
        }

        $AllEntries = Get-WinEvent -FilterHashtable $LogFilter -ComputerName $Server

        $AllEntries | ForEach-Object { 
            $entry = [xml]$_.ToXml()
            [array]$Output += New-Object PSObject -Property @{
                TimeCreated = $_.TimeCreated
                User = $entry.Event.UserData.EventXML.User
                IPAddress = $entry.Event.UserData.EventXML.Address
                EventID = $entry.Event.System.EventID
                ServerName = $Server
            }        
        } 

    }

    $FilteredOutput += $Output | Select-Object TimeCreated, User, ServerName, IPAddress, 
    @{Name='Action';Expression={
        if ($_.EventID -eq '21'){"logon"}
        if ($_.EventID -eq '22'){"Shell start"}
        if ($_.EventID -eq '23'){"logoff"}
        if ($_.EventID -eq '24'){"disconnected"}
        if ($_.EventID -eq '25'){"reconnection"}
        }
    }

    $FilteredOutput | Sort-Object TimeCreated 

}

&{foreach ($h in $all_hosts) {

Invoke-Command -ComputerName $h -Credential $cred -ScriptBlock $script_block -ArgumentList $StartTime

}} | Select-Object TimeCreated, User, ServerName, IPAddress, Action | Export-Csv -Path $log_path -NoTypeInformation 
