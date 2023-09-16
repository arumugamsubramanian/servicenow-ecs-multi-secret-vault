package com.snc.discovery;

import com.azure.core.http.HttpClient;
import com.azure.core.http.ProxyOptions;
import com.azure.core.http.okhttp.OkHttpAsyncHttpClientBuilder;
import com.azure.identity.EnvironmentCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import okhttp3.OkHttpClient;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class AzureKeyVaultCredentialResolver extends CredentialResolver{

    public static final String AZURE_KEY_VAULT_NAME_PROPERTY = "ext.cred.azure.vault.name";
    public static final String PROXY_HOST_PROPERTY = "ext.cred.azure.vault.proxy.host";
    public static final String PROXY_PORT_PROPERTY = "ext.cred.azure.vault.proxy.port";


    public Map azureKeyVaultCredResolve(String credId, String credType, String azureVaultAddress, String azureProxyHostProperty, int azureProxyPortProperty, boolean azureIsProxyEnabled) throws IOException {
        // Connect to vault and retrieve credential
        try {
            // the resolved credential is returned in a HashMap...
            Map result = new HashMap();

//		windows, linux, unix creds
            String username = "";
            String password = "";
            String passphrase = "";
            String private_key = "";
//		azure creds
            String azureClientId = "";
            String azureTenantId = "";
            String azureSecretKey = "";
// 		aws creds
            String awsAccessKey = "";
            String awsSecretKey = "";
//		snmpv3
            String snmpv3PrivacyCredId = null;
            Map<String, String> snmpv3PrivacyKeyTags = new HashMap<>();
            String snmpv3AuthProtocol = "";
            String snmpv3AuthKey = "";
            String snmpv3PrivacyProtocol = "";
            String snmpv3PrivacyKey = "";
            KeyVaultSecret snmpv3PrivacyCredSecret = null;

            Map<String, String> tags = new HashMap<>();

            fLogger.info("Check if the Azure Environment Variables are set. This is mandatory for this integration to work");
            if (System.getenv("AZURE_CLIENT_ID") == null || System.getenv("AZURE_CLIENT_SECRET") == null || System.getenv("AZURE_TENANT_ID") == null) {
                fLogger.error("ENV AZURE_CLIENT_ID || AZURE_CLIENT_SECRET || AZURE_TENANT_ID is missing");
                throw new RuntimeException("AZURE Client Secrets are missing. Please set as System Environment Variables");
            }

            if(isNullOrEmpty(azureVaultAddress)) {
                fLogger.error("[Vault] INFO - CredentialResolver " + azureVaultAddress + " not set!");
            }

            if (azureIsProxyEnabled) {
                fLogger.info("Using Proxy Host : " + azureProxyHostProperty);
		        fLogger.info("Using Proxy Port : " + azureProxyPortProperty);
		        fLogger.info("Proxy enabled : " + true);
            }

            fLogger.info("azureVaultAddress : " + azureVaultAddress);


            SecretClient secretClient;

            if (azureIsProxyEnabled) {
                OkHttpClient newClient = getTrustAllCertsClient();
                HttpClient httpClient = new OkHttpAsyncHttpClientBuilder(newClient)
                        .proxy(new ProxyOptions(ProxyOptions.Type.HTTP, new InetSocketAddress(azureProxyHostProperty, azureProxyPortProperty)))
                        .build();

//				note: if you are using user-provided vault URI, disable the challenge resource verification. https://devblogs.microsoft.com/azure-sdk/guidance-for-applications-using-the-key-vault-libraries/ -> .disableChallengeResourceVerification()
                secretClient = new SecretClientBuilder()
                        .vaultUrl(azureVaultAddress)
                        .credential(new EnvironmentCredentialBuilder().httpClient(httpClient).build())
                        .httpClient(httpClient)
                        .buildClient();
            } else {
                OkHttpClient newClient = getTrustAllCertsClient();
                HttpClient httpClient = new OkHttpAsyncHttpClientBuilder(newClient).build();
                secretClient = new SecretClientBuilder()
                        .vaultUrl(azureVaultAddress)
                        .credential(new EnvironmentCredentialBuilder().httpClient(httpClient).build())
                        .httpClient(httpClient)
                        .buildClient();
            }

            KeyVaultSecret retrievedSecret = secretClient.getSecret(credId);

            if (credType == "snmpv3") {
                snmpv3PrivacyCredSecret = secretClient.getSecret(snmpv3PrivacyCredId);
                snmpv3PrivacyKeyTags = snmpv3PrivacyCredSecret.getProperties().getTags();
            }

            tags = retrievedSecret.getProperties().getTags();

            if (isNullOrEmptyMap(tags)) {
                fLogger.error("Every secrets in Azure Key vault for secrets should have mandatory tags");
                throw new RuntimeException("tags like type, username is missing. Please add to secrets");
            }

            String credTypeFromAzure = null;

            if (!tags.containsKey("type")) {
                fLogger.error("type was not defined correctly in azure w.r.t to servicenow credentials");
                throw new RuntimeException("type was not defined correctly in azure w.r.t to servicenow credentials");
            } else {
                credTypeFromAzure = tags.get("type").trim();
            }

            if (tags == null || credTypeFromAzure == null || !credTypeFromAzure.equalsIgnoreCase(credType)) {
                fLogger.error("type was defined incorrectly in azure w.r.t to servicenow credentials");
                throw new RuntimeException("type was defined incorrectly in azure w.r.t to servicenow credentials");
            }

            switch(credType) {
                // for below listed credential type , just retrieve username and password
                case "windows":
                case "ssh_password": // Type SSH deprecated in ServiceNow
                case "vmware":
                case "jdbc":
                case "jms":
                case "basic":
                    if (tags == null || credTypeFromAzure == null || tags.get("username") == null) {
                        fLogger.error("username was not defined in azure secret as tags");
                        throw new RuntimeException("username was not defined in azure secret as tags");
                    }
                    username = tags.get("username").trim();
                    password = retrievedSecret.getValue();

                    result.put(VAL_USER, username);
                    result.put(VAL_PSWD, password);
                    break;

                // for below listed credential type , retrieve user name, password, ssh_passphrase, ssh_private_key
                case "ssh_private_key":
                    if (tags == null || credTypeFromAzure == null || tags.get("username") == null) {
                        fLogger.error("username was not defined in azure secret as tags");
                        throw new RuntimeException("username was not defined in azure secret as tags");
                    }
                    username = tags.get("username").trim();
                    private_key = retrievedSecret.getValue();

                    result.put(VAL_USER, username);
                    result.put(VAL_PKEY, private_key);
                    break;
                case "azure":
                    azureClientId = tags.get("azure_client_id").trim();
                    azureTenantId = tags.get("azure_tenant_id").trim();
                    azureSecretKey = retrievedSecret.getValue();

                    result.put(AZURE_SECRET_KEY, azureSecretKey);
                    result.put(AZURE_CLIENT_ID, azureClientId);
                    result.put(AZURE_TENANT_ID, azureTenantId);
                    break;

                case "aws":
                    awsAccessKey = tags.get("aws_access_key").trim();
                    awsSecretKey = retrievedSecret.getValue();

                    result.put(VAL_USER, awsAccessKey);
                    result.put(VAL_PSWD, awsSecretKey);
                    break;
                case "snmpv3":
                    username = tags.get("username").trim();
                    snmpv3AuthProtocol = tags.get("snmpv3_auth_protocol").trim();
                    snmpv3AuthKey = retrievedSecret.getValue();
                    snmpv3PrivacyProtocol = snmpv3PrivacyKeyTags.get("snmpv3_privacy_protocol").trim();
                    snmpv3PrivacyKey = snmpv3PrivacyCredSecret.getValue();

                    result.put(VAL_USER, username);
                    result.put(SNMPV3_AUTHENTICATION_PROTOCOL, snmpv3AuthProtocol);
                    result.put(SNMPV3_AUTHENTICATION_KEY, snmpv3AuthKey);
                    result.put(SNMPV3_PRIVACY_PROTOCOL, snmpv3PrivacyProtocol);
                    result.put(SNMPV3_PRIVACY_KEY, snmpv3PrivacyKey);
                    break;
                case "snmp":
                    password = retrievedSecret.getValue();
                    result.put(VAL_PSWD, password);
                    break;
                default:
                    fLogger.error("[Vault] INFO - CredentialResolver- invalid credential type found.");
                    break;
            }
            return result;
        }
        catch (RuntimeException e) {
            fLogger.error("### Unable to connect to Vault: " + azureVaultAddress, e);
            throw new RuntimeException("### Unable to connect to Vault: " + azureVaultAddress, e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (KeyManagementException e) {
            throw new RuntimeException(e);
        }
    }
}
