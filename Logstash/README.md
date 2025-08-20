### Примеры logstash-конфигов

```
if [winlog][event_id] == "5136" and [winlog][event_data][AttributeLDAPDisplayName] == "msPKI-Enrollment-Flag" {
    ruby {
        id => "ruby_get_pki_enrollment_flags"
        path => "/usr/share/logstash/scripts/get_pki_enrollment_flags.rb"
        script_params => { "field" => "[winlog][event_data][AttributeValue]" }
        tag_on_exception => "ruby_exception_in_get_pki_enrollment_flags"
    }
}
```

```
if ([winlog][event_id] == "4657") and ("\Services\CertSvc\Configuration" in [winlog][event_data][ObjectName]) and ([winlog][event_data][ObjectValueName] == "InterfaceFlags") {
    ruby {
        id => "ruby_get_adcs_interfaceflags"
        path => "/usr/share/logstash/scripts/get_adcs_interfaceflags.rb"
        script_params => { "field" => ["[winlog][event_data][OldValue]", "[winlog][event_data][NewValue]"] }
        tag_on_exception => "ruby_exception_in_ruby_get_adcs_interfaceflags"
    }
}
```