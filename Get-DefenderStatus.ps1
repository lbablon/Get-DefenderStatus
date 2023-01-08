<#

.SYNOPSIS
This script is intended to fecth information about Microsoft Defender on all computers in a domain.

.DESCRIPTION
The script must be run from a computer in a domain. The computer must have network access to all computers in the domain and the script me be run by a user with 
sufficient permissions. The script can be run  from a domain controller for that purpose. When running, the script will list every computers on the domain that 
run uder Windows and will query Microsoft Defender status in search for threat detections, inactive Defender processes and outdated signatures. The report is 
generated in HTML and can be sent by email to a specified recipient using the -mailto switch. Unreachable computers need to be investigated and could be caused 
by many things. Most frequent issues are Defender not installed, windows firewalls not allowing the query and computer is not existing anymore but has not been 
cleaned up from Active Directory. 

.EXAMPLE
"./Get-DefenderStatus.ps1" -MailTo l.bablon@contoso.com
Runs the script and sends the report as email

.EXAMPLE
"./Get-DefenderStatus.ps1" -OutputFile "C:\temp\report.html"
Runs the script and save the report in c:\temp\report.html

.INPUTS
OutputFile : specifiy the location where to save the report as a .html file 
MailTo : recipient's email address that will receive the report
Computer : if specified, the script will only query this computer. By default, the script queries all computers from the domain.

.NOTES
Written by : Lucas Bablon
Version : 1.0
Link : https://github.com/lbablon

#>

#required components
#requires -Module ActiveDirectory

#params
param 
(
    [Parameter(Mandatory=$false, HelpMessage="Recipient address for mail notification")]
    [string]$mailto,

    [Parameter(Mandatory=$false, HelpMessage="Export path for csv file")]
    [string]$outputfile=".\MicrosoftDefender-report.html",
    
    [Parameter(Mandatory=$false, HelpMessage="Export path for csv file")]
    [string]$computer
)

##
##VARIABLES
##

$date = Get-Date -format "dd-MM-yyyy"
$fulldate = Get-Date -format "dd-MM-yyyy hh:mm"
$hostname = hostname
$domain = $env:USERDOMAIN

#mail notification configuration
$SmtpServer = "your.smtp-server.com"
$mailfrom = "Defender <user@yourdomain.com>"
$mailsubject = "Defender for $domain - Reported on: "+$date

#html and css styling
$html = "<style>"
$html = $html + "BODY{background-color:white;font-family: Arial;}"
$html = $html + "TABLE{border: 1px;border-collapse: collapse;}"
$html = $html + "TH{border: 1px solid #ddd;padding: 15px;background-color: #300e7b;font-family: Arial;color: white;text-align: left;}"
$html = $html + "TD{border: 1px solid #ddd;padding: 15px;background-color: white;font-family: Arial;}"
$html = $html + "</style>"

#counters reset
$unreachable = 0

##
##SCRIPT
##


if ($computer)
{
    $computers=$computer
    
    Write-Output "`n"
    Write-Output "Fetching $computers"
}
else
{
    #list every windows computer in the domain
    Write-Output "`n"
    Write-Output "Listing Windows computers from domain $domain..."
    
    $computers = Get-ADComputer -filter * -properties *| ? {$_.operatingsystem -like "Windows*"} | select name
    $computerscount = ($computers | measure).count
    
    Write-Output "$computerscount computer(s) has been found.`n"
}

# for every windows compturer in the domain and final object creation
Write-Output "Fetching Microsoft Defender information for computers..."

$i=1

$report = $computers | sort ServerName | % {
    
    #progress bar
    $completed=[math]::round(($i/$computerscount)*100)
    Write-Progress -Activity "Computers requested" -Status "$completed% complete" -PercentComplete $completed
    Start-Sleep -Milliseconds 300

    #clear values from previous run
    $error.clear()
    $DefenderStatus=""
    $Signatures=""
    $lastfullscan=""
    $lastquickscan=""
    $threatdetected=""
    $threatname=""
    $infectedfile=""
    $threatstatus=""
    $infected=""
    $ping=""
    
    $computer = $_
    $computername = $computer.name

    #test if computer is reachable on the network
    $ping = Test-Connection $computername -Count 1 -ErrorAction SilentlyContinue
    
    #if computer responds then get windows defender information
    if ($ping) 
    {

        try
        {
            #get id of the last threat windows defender has detected on the computer
            $ThreatID = Get-MpThreatDetection -CimSession "$computername" | Sort-Object InitialDetectionTime  -Descending | select -First 1 -ExpandProperty ThreatID

            #if a threat has been detected what action took defender
            $ThreatActionID = Get-MpThreatDetection -CimSession "$computername" | Sort-Object InitialDetectionTime  -Descending | select -First 1 -ExpandProperty ThreatStatusID

            switch ( $ThreatActionID ) 
            {
                0 { $Threatstatus = 'Unknown' }
                1 { $Threatstatus = 'Detected' }
                2 { $Threatstatus = 'Cleaned' }
                3 { $Threatstatus = 'Quarantined' }
                4 { $Threatstatus = 'Removed' }
                5 { $Threatstatus = 'Allowed' }
                6 { $Threatstatus = 'Blocked' }
                102 { $Threatstatus = 'QuarantinedFailed' }
                103 { $Threatstatus = 'RemoveFailed' }
                104 { $Threatstatus = 'AllowFailed' }
                105 { $Threatstatus = 'Abondoned' }
                107 { $Threatstatus = 'BlockedFailed' }
            }

            #check if windows defender is enabled on the computer
            $DefenderStatus = Get-MpComputerStatus -CimSession "$computername" | select -ExpandProperty AntivirusEnabled

            switch ( $DefenderStatus ) 
            {
                True { $DefenderStatus = 'Active' }
                False { $DefenderStatus = 'Inactive' }
            }

            #check if protections are up to date on the computer
            $Signatures = Get-MpComputerStatus -CimSession "$computername" | select -ExpandProperty DefenderSignaturesOutOfDate

            switch ( $Signatures ) 
            {
                True { $Signatures = 'Out of date' }
                False { $Signatures = 'Up to date' }
            }

            #last time a full scan of the computer has been performed
            $lastfullscan = Get-MpComputerStatus -CimSession "$computername" | select -ExpandProperty FullScanEndTime

            #last time a quick scan of the computer has been performed
            $lastquickscan = Get-MpComputerStatus -CimSession "$computername" | select -ExpandProperty QuickScanEndTime

            #last threat defender detected on this computer
            $threatdetected = Get-MpThreatDetection -CimSession "$computername" | Sort-Object InitialDetectionTime  -Descending | select -First 1 -ExpandProperty InitialDetectionTime

            #threat type
            $threatname = Get-MpThreat -CimSession "$computername" | where {$_threadID -like "$Threatname"} | select -ExpandProperty ThreatName

            #path to infected file on the computer
            $infectedfile = Get-MpThreatDetection -CimSession "$computername" | Sort-Object InitialDetectionTime  -Descending | select -First 1 -ExpandProperty Resources

            if ($infectedfile)
            { 
                $infected = 1
            } 
        }
        catch
        {
            $erreur = 1
        }

        #if defender does not respond on the computer then set default values in results
        if ($error) 
        {
            $DefenderStatus = "Inactive"
            $Signatures = "-"
            $lastfullscan = "-"
            $lastquickscan = "-"
            $threatdetected = "-"
            $threatname = "-"
            $infectedfile = "-"
            $threatstatus = "-"
            $infected = 0
        }
    } 
    else 
    {
        $DefenderStatus = "Computer cannot be reached"
        $Signatures = "-"
        $lastfullscan = "-"
        $lastquickscan = "-"
        $threatdetected = "-"
        $threatname = "-"
        $infectedfile = "-"
        $threatstatus = "-"
        $infected = 0
        $unreachable++
    }

    #results
    New-Object -TypeName PSobject -Property @{
    
        ServerName = $computer.name
        ipv4Address = $ping.IPV4Address
        DefenderStatus = $DefenderStatus
        IsOutOfDate = $Signatures
        LastFullScan = $lastfullscan
        LastQuickScan =  $lastquickscan
        ThreatDetected =  $threatdetected
        InfectedFile = $infectedfile
        InfectedComputer = $infected
        ThreatName = $threatname
        ThreatStatus = $Threatstatus

    }

    $i++
}

Write-Output "Done`n"

##
##REPORT CREATION
##

#html main report
$reporthtml=$report | 
    select @{Name="Server name";Expression={$_.ServerName}},@{Name="IPv4 Address";Expression={$_.ipv4Address}},@{Name="Protection";Expression={$_.DefenderStatus}},@{Name="Out of date";Expression={$_.IsOutofDate}},@{Name="Last full scan";Expression={$_.LastFullScan}},@{Name="Last quick scan";Expression={$_.LastQuickScan}},@{Name="Threat detected";Expression={$_.ThreatDetected}},@{Name="Threat name";Expression={$_.ThreatName}},@{Name="Infected file";Expression={$_.InfectedFile}},@{Name="Action";Expression={$_.ThreatStatus}} | 
    ConvertTo-Html -Head $html

#statistics
$totalcomputers = ($computers | Measure-Object).count
$unreachablecomputers = $unreachable
$inactivecomputers = ($report | ? DefenderStatus -eq "Inactive" | Measure-Object).count
$outofdatecomputers = ($report | ? IsOutofDate -e "Out of date" | Measure-Object).count
$infectedcomputers = ($report | ? InfectedComputer -eq "1" | Measure-Object).count

$reportoverview = New-Object -TypeName PSobject -Property @{

    TotalComputers = $totalcomputers
    UnreachableComputers = $unreachablecomputers
    InactiveComputers = $inactivecomputers
    OutOfdateComputers = $outofdatecomputers
    InfectedComputers = $infectedcomputers

}

#report overview as html
$reportoverview = $reportoverview | 
    select @{Name="Total computers";Expression={$_.TotalComputers}},@{Name="Unreachable";Expression={$_.UnreachableComputers}},@{Name="Unprotected";Expression={$_.InactiveComputers}},@{Name="Out of date";Expression={$_.OutOfDateComputers}},@{Name="Infected";Expression={$_.InfectedComputers}} | 
    ConvertTo-Html -head $html

#html introduction message for outputfile
$htmlintro = @"
    This email has been generated on $FullDate by script 'Get-DefenderStatus.ps1' on server $hostname<br>
    <br>
"@

#html overview statistics text
$htmloverview = @"
    <br>
    <b>Report overview explanation :</b> 
    <ul>
        <li>Total computers : number of computer in the domain $domain that run on Windows</li>
        <li>Unreachable : at the time the script runned, number of computers that could not have been reached on the network</li>
        <li>Unprotected : number of computers that are reachable on the network but not protected by Windows Defender</li>
        <li>Out of Date : number of computers with active protection but out of date signatures</li>
        <li>Infected : number of computers where Windows Defender has detected a malicious object</li>
    </ul>
"@

#instructions text
$htmlinstructions = @"
<br>
    <b>The following scenarios will require further investigation on the computer :</b> 
    <ul>
        <li>The computer cannot be reached</li>
        <li>The protection is not active on the computer</li>
        <li>Signatures are not up to date</li>
        <li>No quick scan performed since a week ago</li>
        <li>A threat has been detected on the computer</li>
    </ul>

"@

#full report as html file
$htmlintro+"<br>"+$reportoverview+$htmloverview+$reporthtml+$htmlinstructions | Out-File $outputfile

Write-Output "Full report has been saved in "(Get-ChildItem $outputfile).versioninfo.filename"`n"

##
##MAIL
##

if ($mailto)
{

#display only computers with no active protection or where threats have been detected in mail body
$report = $report | 
    sort ServerName | 
    ? { ($_.ThreatDetected -ne $null -and $_.ThreatDetected -notlike "-") -or $_.DefenderStatus -like "Inactive" } | 
    select  @{Name="Server name";Expression={$_.ServerName}},@{Name="IPv4 Address";Expression={$_.ipv4Address}},@{Name="Protection";Expression={$_.DefenderStatus}},@{Name="Signatures";Expression={$_.IsOutofDate}},@{Name="Last full scan";Expression={$_.LastFullScan}},@{Name="Last quick scan";Expression={$_.LastQuickScan}},@{Name="Threat detected";Expression={$_.ThreatDetected}},@{Name="Threat name";Expression={$_.ThreatName}},@{Name="Infected file";Expression={$_.InfectedFile}},@{Name="Action";Expression={$_.ThreatStatus}} | 
    ConvertTo-Html -Head $html

#insert introduction into the top part of the email message
$mailtop = @"
    This email has been generated on $FullDate by script 'Get-DefenderStatus.ps1' on server $hostname<br>
    <br>
    The Full report can be found attached to this message.
    <br>
"@

#insert information into bottom part of the email messae
$mailbot = @"
    <br>
    <b>The following scenarios will require further investigation on the computer :</b> 
    <ul>
        <li>The computer cannot be reached</li>
        <li>The protection is not active on the computer</li>
        <li>Signatures are not up to date</li>
        <li>No quick scan performed since a week ago</li>
        <li>A threat has been detected on the computer</li>
    </ul>
    <br>
    <b>Report overview explanation :</b> 
    <ul>
        <li>Total computers : number of computer in the domain $domain that run on Windows</li>
        <li>Unreachable : at the time the script runned, number of computers that could not have been reached on the network</li>
        <li>Unprotected : number of computers that are reachable on the network but not protected by Windows Defender</li>
        <li>Out of Date : number of computers with active protection but out of date signatures</li>
        <li>Infected : number of computers where Windows Defender has detected a malicious object</li>
    </ul>
"@

#mail params
$MailParam = @{

    Subject = $mailsubject
    Body = $reportoverview+$report+$mailbot+$mailtop | Out-String
    From = $mailfrom
    To = $mailto
    SmtpServer = $smtpserver

}

#send recap mail with full report as attachment 
Send-MailMessage @MailParam -BodyAsHtml -Attachments $outputfile
Write-Output "Report has been sent by email to $mailto.`n"
}

#$top+$reportoverview+$reporthtml+$bot | Out-File $outputfile
