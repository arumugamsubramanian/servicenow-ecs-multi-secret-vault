# servicenow-ecs-azure-key-vault
ServiceNow External Credential Storage integration with Azure Key Vault

## setup
* Upload the jar file to servicenow instance under mid server jars

* https://github.com/arumugamsubramanian/servicenow-ecs-multi-secret-vault/releases


![img_1.png](images%2Fimg_1.png)

## file based credential setup

* copy [creds.properties](setup%2Ffile-vault%2Fcreds.properties) to mid server
* Add mid server properties in config.xml
```text
<parameter name="ext.cred.file.path" value="/opt/snc_mid_server/creds.properties"/>
```
* Create a credential in below format

![img.png](images%2Fimg.png)

* creds in file should have 
```text
filevault-linux.ssh_password.user=root
filevault-linux.ssh_password.pswd=xxx

Pattern:
credID.credtype.user
```

### Note: The cred ID should always start with `file`

## Azure Key Vault Setup

### Note: The cred ID should always start with `akv`

## Hashicorp Vault Setup