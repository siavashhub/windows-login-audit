$script1= {
[array]$ServersToQuery = (hostname)
[datetime]$StartTime = "May 1, 2020"

    foreach ($Server in $ServersToQuery) {

        $LogFilter = @{
            LogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
            ID = 21, 23, 24, 25
            StartTime = $StartTime
            }

        $AllEntries = Get-WinEvent -FilterHashtable $LogFilter -ComputerName $Server

        $AllEntries | Foreach { 
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

    $FilteredOutput += $Output | Select TimeCreated, User, ServerName, IPAddress, @{Name='Action';Expression={
                if ($_.EventID -eq '21'){"logon"}
                if ($_.EventID -eq '22'){"Shell start"}
                if ($_.EventID -eq '23'){"logoff"}
                if ($_.EventID -eq '24'){"disconnected"}
                if ($_.EventID -eq '25'){"reconnection"}
                }
            }

    $Date = (Get-Date -Format s) -replace ":", "."

    $FilteredOutput | Sort TimeCreated 

}
$cred= Get-Credential

[array]$svs = "Host-01","Host-02","Host-03","Host-04","Host-05"

&{foreach ($sv in $svs) {

Invoke-Command -ComputerName $sv -Credential $cred -ScriptBlock $script1

}} | Export-Csv -Path "C:\host-audit-20200901-allhosts.csv"
