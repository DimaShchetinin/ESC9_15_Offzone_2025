# Hunts

### Certificate request NTLM+RPC
```sql
winlog.event_id:(4886 OR 4887 OR 4888 OR 4889) AND winlog.event_data.DCOMorRPC:"RPC" AND winlog.event_data.AuthenticationService:"NTLM"
```

### Certificate request RPC
```sql
winlog.event_id:(4886 OR 4887 OR 4888 OR 4889) AND winlog.event_data.DCOMorRPC:"RPC"
```

### Certificate request by a non-standard application
The list of applications is not complete; specialized software is also possible. This hunt needs to be adapted to your environment.
```sql
winlog.event_id:4886 AND 
winlog.event_data.RequestClientInfo:* AND 
NOT winlog.event_data.RequestClientInfo:(*MMC.EXE* OR *taskhostw.exe* OR *dmcertinst.exe* OR *certreq.exe*)
```

### Certificate request with non-standard attributes

This hunt needs to be adapted to your environment.
```sql
winlog.event_id:4886 AND 
winlog.event_data.RequestClientInfo:* AND 
(
    winlog.event_data.RequestCSPProvider:"Microsoft Strong Cryptographic Provider" AND 
    NOT winlog.event_data.RequestClientInfo:*certreq.exe*
)
```

### Certificate request with non-standard attributes

This hunt needs to be adapted to your environment.
```sql
winlog.event_id:4886 AND winlog.event_data.Attributes:/.*CertificateTemplate\:.+/ AND NOT winlog.event_data.Attributes:(/.+UserAgent\:.+/ OR /.+ProxyURI\:.+\:.+/)
```

### U2U TGS request with host account
```sql
winlog.event_id:4769 AND winlog.event_data.ServiceName:/.+$/ AND winlog.event_data.TicketOptionsDescription:"Enc-tkt-in-skey"
{
  "query": {
    "script": {
      "script": {
        "lang": "painless",
        "source": "String ServiceName = doc['winlog.event_data.ServiceName'].value.trim().toLowerCase();String TargetUserName = doc['winlog.event_data.TargetUserName'].value.trim().toLowerCase();int first_TargetUserName = TargetUserName.indexOf('@');  String AccountName = first_TargetUserName > 0 ? TargetUserName.substring(0, first_TargetUserName) : TargetUserName;return ServiceName == AccountName;"
      }
    }
  }
}
```

### TGT request specific to certipy
```json
{
  "query": {
    "bool": {
      "must": [{ "query_string": {"query": "winlog.event_id:4768 AND winlog.event_data.PreAuthType:16"} }],
      "filter": [{ "match_phrase": {
        "winlog.event_data.ClientAdvertizedEncryptionTypes": "\n\t\tAES256-CTS-HMAC-SHA1-96\n\t\tAES128-CTS-HMAC-SHA1-96"
        }}]
    }
  }
}
```

### U2U TGS request specific to certipy
```json
{
  "query": {
    "bool": {
      "filter": [
        {
          "match_phrase": {
            "winlog.event_data.ClientAdvertizedEncryptionTypes": "\n\t\tAES256-CTS-HMAC-SHA1-96\n\t\tRC4-HMAC-NT"
          }
        }
      ],
      "must": [
        {
          "query_string": {
            "query": "winlog.event_id:4769 AND winlog.event_data.TicketOptionsDescription:\"Enc-tkt-in-skey\"\n"
          }
        }
      ]
    }
  }
}

```