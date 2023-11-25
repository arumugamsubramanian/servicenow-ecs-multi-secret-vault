# servicenow-ecs-azure-key-vault
ServiceNow External Credential Storage integration with Azure Key Vault

### Documentation

* https://docs.servicenow.com/bundle/vancouver-platform-security/page/product/credentials/concept/c_ExternalCredentialStorage.html
* Credit: ServiceNow
![img_3.png](images%2Fimg_3.png)
* Credit: Hashicorp Vault
![img_4.png](images%2Fimg_4.png)

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
* configure the subscription in a tenant and then create an application under subscription and assign permissions
* set the environment variable in mid server
```shell
AZURE_CLIENT_ID
AZURE_CLIENT_SECRET
AZURE_TENANT_ID
```
Add mid-server properties in config.xml. Add proxy properties if proxy needed
```text
<parameter name="ext.cred.azure.vault.name" value="xxx.vault.azure.net"/> # get the vault name without https:// from vault URL. Eg., https://xxx.vault.azure.net/

<parameter name="ext.cred.azure.vault.proxy.host" value=""/>

<parameter name="ext.cred.azure.vault.proxy.port" value=""/> # 8080
```
* Add credentials types as tags in Azure Key vault.

## Hashicorp Vault Setup

### Note: The cred ID should always start with `hv/`

Credit: Thanks to Hashicorp Vault for the code reference. This integration was forked from https://github.com/hashicorp/vault-servicenow-credential-resolver

* follow [README.md](setup%2Fhashicorp-vault%2FREADME.md) to setup local vault server in docker
* Add mid-server properties in config.xml
```text
<parameter name="ext.cred.hashicorp.vault.address" value="http://127.0.0.1:8200"/>

<parameter name="ext.cred.hashicorp.vault.ca" value=""/>

<parameter name="ext.cred.hashicorp.vault.tls_skip_verify" value="true"/>

<parameter name="ext.cred.hashicorp.vault.username" value="servicenow"/>

<parameter name="ext.cred.hashicorp.vault.password" value="servicenow"/>
```
* credentials ID format in ServiceNow credentials
```text
hv/secret/data/linux # always start with 'hv/' without quotes, otherwise it will not consider hashicorp vault as secret provider.

Format: 
hv/<secret_path_in_vault>
```
![img_2.png](images%2Fimg_2.png)