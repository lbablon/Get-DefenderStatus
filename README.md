
# Get-DefenderStatus.ps1 - fecth information about Microsoft Defender on computers.

The script is intended to fecth information about Microsoft Defender on remote computers. The scripts will then generate an html report about AV activities.

## Usage

The script must be run from a computer in a domain. The computer must have network access to all computers in the domain and the script me be run by a user with 
sufficient permissions. The script can be run from a domain controller for that purpose. 

When running, the script will list every computers on the domain that run uder Windows and will query Microsoft Defender status in search for threat detections, inactive Defender processes and outdated signatures.

Sometimes computers cannot be reached. There can be many causes including :

- Defender is not installed on the computer.
- Windows firewall does not allow the connection.
- The computer simply does not exist anymore but has not been cleaned up from Active Directory. 

The mail parameters can be changed so that it suits to your environnement. To do so, just modify the smtp parameters at the beginning of the script : 

```
#mail notification configuration
$SmtpServer = "your.smtp-server.com"
$mailfrom = "Defender <user@yourdomain.com>"
$mailsubject = "Defender for $domain - Reported on: "+$date
```

## Parameters

- **[-outputfile]**, Checkpoint management server's ip address or fqdn.
- **[-mailto]**, user with sufficient permissions on the management server.
- **[-computer]**, if specified, the script will only query this computer. By default, the script queries all computers from the domain.

## Examples

```
"./Get-DefenderStatus.ps1" -computer "Computer-001"
```

Runs the script for the remote computer named "Computer-001".

```
"./Get-DefenderStatus.ps1" -MailTo l.bablon@contoso.com
```

Runs the script for all computers and sends the report as email.

```
"./Get-DefenderStatus.ps1" -OutputFile "C:\temp\report.html"
```

Runs the script for all computers and save the report in c:\temp\report.html.
