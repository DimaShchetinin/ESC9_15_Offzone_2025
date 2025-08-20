# Подготовка GOAD

1. Установить GOAD по [инструкции](https://orange-cyberdefense.github.io/GOAD/installation/), повысив версию хоста SRV03.

    Для этого нужно изменить файл `ad\GOAD\providers\vmware\Vagrantfile`

    ```
    boxes = [
      # windows server 2019
      { :name => "GOAD-DC01",  :ip => "{{ip_range}}.10", :box => "StefanScherer/windows_2019", :box_version => "2021.05.15", :os => "windows", :cpus => 2, :mem => 3000},
      # windows server 2019
      { :name => "GOAD-DC02",  :ip => "{{ip_range}}.11", :box => "StefanScherer/windows_2019", :box_version => "2021.05.15", :os => "windows", :cpus => 2, :mem => 3000},
      # windows server 2016
      { :name => "GOAD-DC03",  :ip => "{{ip_range}}.12", :box => "StefanScherer/windows_2016", :box_version => "2017.12.14", :os => "windows", :cpus => 2, :mem => 3000},
      # windows server 2019
      { :name => "GOAD-SRV02", :ip => "{{ip_range}}.22", :box => "StefanScherer/windows_2019", :box_version => "2021.05.15", :os => "windows", :cpus => 2, :mem => 6000},
      # windows server 2016
      # { :name => "GOAD-SRV03", :ip => "{{ip_range}}.23", :box => "StefanScherer/windows_2016", :box_version => "2019.02.14", :os => "windows", :cpus => 2, :mem => 5000}
      { :name => "GOAD-SRV03", :ip => "{{ip_range}}.23", :box => "StefanScherer/windows_2022", :box_version => "2021.08.23", :os => "windows", :cpus => 2, :mem => 5000}
    ]
    ```
2. Дополнительно запустить плейбук по установке ELK+Winlogbeat:
    ```
    provision elk
    ```
Если плейбук не работает, то можно установить самому:
- Установить [Docker compose](https://docs.docker.com/compose/install/)
- Запустить Elasticsearch+Kibana из файла `docker-compose.yml`
- [Установить](https://www.elastic.co/docs/reference/beats/winlogbeat/winlogbeat-installation-configuration#installation) (Step 1) Winlogbeat на DC03 и SRV03
- [Донастроить](https://www.elastic.co/docs/reference/beats/winlogbeat/winlogbeat-installation-configuration#set-connection) (Step 2-6) Winlogbeat для отправки событий в установленный Elasticsearch.
Конфиг отправки будет выглядеть примерно так `C:\Program Files\Winlogbeat\winlogbeat.yml`:
    ```yml
    output.elasticsearch:
      hosts: ["192.168.56.100:9200"]
      username: "elastic"
      password: "elastic"
      pipeline: "winlogbeat-%{[agent.version]}-routing"
    ```
3. Настроить политики аудита на DC03 и SRV03 (ADCS).
    ```
    Category/Subcategory                      Setting
    System
      Security System Extension               Success
      Security State Change                   Success
    Logon/Logoff
      Logon                                   Success and Failure
      Account Lockout                         Failure
      Special Logon                           Success and Failure
    Object Access
      Registry                                Success and Failure
      Certification Services                  Success and Failure
      File Share                              Success
      Other Object Access Events              Success
    Privilege Use
      Sensitive Privilege Use                 Success
    Policy Change
      Audit Policy Change                     Success
      MPSSVC Rule-Level Policy Change         Success
    Account Management
      Computer Account Management             Success and Failure
      Application Group Management            Success
      User Account Management                 Success and Failure
    DS Access
      Directory Service Access                Success and Failure
      Directory Service Changes               Success and Failure
    Account Logon
      Kerberos Service Ticket Operations      Success and Failure
      Kerberos Authentication Service         Success and Failure
      Credential Validation                   Success and Failure
    ```

4. Настроить аудит объектов Active Directory.
- На хосте DC03 под УЗ daenerys.targaryen → Win+R → adsiedit.msc
- Нажмите правой кнопкой мыши на "ADSI Edit" и выберите "Connect to"
- Подключитесь к Default Naming Context:

    ![adsi_dnc.png](adsi_dnc.png)
- Нажать правой кнопкой мыши по домену "DC=essos,DC=local", выберите Properties → Security → Advanced → Auditing → Add → Select Principal → Everyone

  Так как мы работаем в условиях тестовой среды, то можем себе позволить выбрать расширенные настройки аудита:

    ![ad_audit.png](ad_audit.png)

5. Настроить аудит объектов Active Directory Certificate Services.
- На хосте DC03 под УЗ daenerys.targaryen → Win+R → adsiedit.msc
- Нажмите правой кнопкой мыши на "ADSI Edit" и выберите "Connect to"
- Подключитесь к Configuration:

    ![adsi_conf.png](adsi_conf.png)

- Открыть каталог CN=Configuration,DC=essos,DC=local → CN=Services → CN=Public Key Services

- Нажать правой кнопкой мыши по "CN=Public Key Services", выберите Properties → Security → Advanced → Auditing → Add → Select Principal → Everyone

  Так как мы работаем в условиях тестовой среды, то можем себе позволить выбрать расширенные настройки аудита:

    ![pks_audit.png](pks_audit.png)

6. Настроить аудит Active Directory Certificate Services
- На хосте SRV03 под УЗ daenerys.targaryen → Win+R → cmd
- Выполните команды:
  ```
  certutil -setreg CA\AuditFilter 127
  certutil -setreg policy\EditFlags +EDITF_AUDITCERTTEMPLATELOAD
  net stop certsvc && net start certsvc
  ```

7. Настроить аудит ключей реестра.
- На хосте DC03 под УЗ daenerys.targaryen → Win+R → gpedit.msc
- Правой кнопкой мыши по Default Domain Policy → Edit
- Computer Configuration → Policies → Windows Settings → Security Settings → Registry → Add key

    Для каждого ключа реестра из списка выбрать аудит со скриншота
    ```
    MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration
    MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL
    MACHINE\SYSTEM\CurrentControlSet\Services\Kdc
    
    Дополнительно добавить Query value, Enumerate Subkeys: 
    MACHINE\SOFTWARE\Yubico\YubiHSM\
    ```
    
    ![registry_audit.png](registry_audit.png)
    
8. Сделать снапшоты SRV03 и DC03 до установки обновлений
9. Включить обновления на SRV03 и DC03. Проще всего сделать с помощью [enable updates.bat](https://github.com/tsgrgo/windows-update-disabler)
10. Обновить SRV03 и DC03
11. Установить [KALI](https://www.kali.org/get-kali/#kali-virtual-machines) и актуальную версию [certipy](https://github.com/ly4k/Certipy/wiki/04-‐-Installation) (лучше из исходного кода)