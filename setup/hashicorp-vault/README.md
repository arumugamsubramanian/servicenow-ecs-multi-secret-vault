# Hashicorp vault setup

* Install vault in docker as vault server
```shell
docker run -d --cap-add=IPC_LOCK \
-e 'VAULT_LOCAL_CONFIG={"storage": {"file": {"path": "/vault/file"}}, "listener": [{"tcp": { "address": "0.0.0.0:8200", "tls_disable": true}}], "default_lease_ttl": "168h", "max_lease_ttl": "720h", "ui": true}' \
-v $(PWD)/setup/hashicorp-vault:/vault/file \
-p 8200:8200 \
--name vault \
hashicorp/vault server
```
* Login to docker container
```shell
docker exec -it vault sh
```
* Vault setup
```shell
export VAULT_ADDR=http://127.0.0.1:8200
vault status
vault operator init
vault operator unseal # three times
vault login # use root token
```
* List the secrets
```shell
vault secrets list
```
* Enable secret engine and create secrets
```shell
vault secrets enable -path=secret kv
vault kv put -mount=secret linux password="root123" username="root"
vault kv put -mount=secret foo password="root123" username="root"
```
* Create policy to provide access to the above secrets
```shell
vault policy write my-policy - << EOF
    # Dev servers have version 2 of KV secrets engine mounted by default, so will
    # need these paths to grant permissions:
    path "secret/data/*" {
      capabilities = ["read"]
    }
    
    path "secret/data/foo" {
      capabilities = ["read"]
    }
EOF

vault policy list
vault policy read my-policy
```
* create userpass path as 'servicenow'. Use `userpass` as vault auth method
* username can be anything because you are passing as mid-server config param
```shell
vault auth enable -path=servicenow userpass
  
vault write auth/servicenow/users/servicenow \
  password=servicenow \
  policies=my-policy
```