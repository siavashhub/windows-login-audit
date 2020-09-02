$Server = (hostname)
$log_path = "C:\host-audit-20200901-allhosts.csv"
[datetime]$StartTime = "May 1, 2020"

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

$FilteredOutput = $Output | Select-Object TimeCreated, User, ServerName, IPAddress, 
@{Name='Action';Expression={
    if ($_.EventID -eq '21'){"logon"}
    if ($_.EventID -eq '22'){"Shell start"}
    if ($_.EventID -eq '23'){"logoff"}
    if ($_.EventID -eq '24'){"disconnected"}
    if ($_.EventID -eq '25'){"reconnection"}
    }
}


$FilteredOutput | Sort-Object TimeCreated | Export-Csv -Path $log_path -NoTypeInformation
