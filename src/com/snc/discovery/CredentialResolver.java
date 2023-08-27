package com.snc.discovery;

import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import com.azure.core.credential.TokenCredential;
import com.azure.core.http.okhttp.OkHttpAsyncHttpClientBuilder;
import com.azure.identity.EnvironmentCredentialBuilder;
import com.snc.automation_common.integration.creds.IExternalCredential;
import com.snc.core_automation_common.logging.Logger;
import com.snc.core_automation_common.logging.LoggerFactory;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.Request;
import com.azure.core.http.*;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import java.util.logging.ConsoleHandler;
import java.util.logging.Level;

import javax.net.ssl.*;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import com.azure.identity.ClientSecretCredential;
import com.azure.identity.*;
import com.azure.core.credential.TokenCredential;

import java.util.Arrays;
import java.util.Collections;

import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;

/**
 * Custom External Credential Resolver for Azure credential vault.
 */
public class CredentialResolver implements IExternalCredential{

//	extend the permissible names of arguments passed INTO the resolve()
	public static final String AZURE_SECRET_KEY = "secret_key";
	public static final String AZURE_CLIENT_ID = "client_id";
	public static final String AZURE_TENANT_ID = "tenant_id";
	public static final String AWS_ACCESS_KEY = "AWSServiceAccount.aws.user";
	public static final String AWS_SECRET_KEY = "AWSServiceAccount.aws.pswd";
	public static final String SNMPV3_ARG_PRIVACY_ID = "privacy_credential_id";
	public static final String SNMPV3_AUTHENTICATION_PROTOCOL = "authentication_protocol";
	public static final String SNMPV3_AUTHENTICATION_KEY = "authentication_key";
	public static final String SNMPV3_PRIVACY_PROTOCOL = "privacy_protocol";
	public static final String SNMPV3_PRIVACY_KEY = "privacy_key";

	//	starts here
	public static final String AZURE_KEY_VAULT_NAME_PROPERTY = "ext.cred.azure.vault.name";

	public static final String PROXY_HOST_PROPERTY = "ext.cred.azure.vault.proxy.host";

	public static final String PROXY_PORT_PROPERTY = "ext.cred.azure.vault.proxy.port";
	private String azureVaultAddress = "";
	private String azureVaultName;

	private String getProxyHostProperty;
	private int getProxyPortProperty;

	private boolean isProxyEnabled;
	// Logger object to log messages in agent.log
	private static final Logger fLogger = LoggerFactory.getLogger(CredentialResolver.class);
	public CredentialResolver() {
	}
	
	/**
	 * Config method with preloaded config parameters from config.xml.
	 * @param configMap - contains config parameters with prefix "ext.cred" only.
	 */
	@Override
	public void config(Map<String, String> configMap) {
		//Note: To load config parameters from MID config.xml if not available in configMap.
		//propValue = Config.get().getProperty("<Parameter Name>")

		azureVaultName = configMap.get(AZURE_KEY_VAULT_NAME_PROPERTY);

		isProxyEnabled = !(isNullOrEmpty(configMap.get(PROXY_HOST_PROPERTY)) && isNullOrEmpty(configMap.get(PROXY_PORT_PROPERTY)));

		fLogger.info("Using Proxy Host : " + configMap.get(PROXY_HOST_PROPERTY));
		fLogger.info("Using Proxy Port : " + configMap.get(PROXY_PORT_PROPERTY));
		fLogger.info("Proxy enabled : " + isProxyEnabled);
		if (isProxyEnabled) {
			getProxyHostProperty = configMap.get(PROXY_HOST_PROPERTY);
			getProxyPortProperty = Integer.parseInt(configMap.get(PROXY_PORT_PROPERTY));
		}

		fLogger.info("azureVaultName : " + azureVaultName);
		if(isNullOrEmpty(azureVaultName))
			fLogger.error("[Vault] INFO - CredentialResolver " + AZURE_KEY_VAULT_NAME_PROPERTY + " not set!");

		azureVaultAddress = "https://" + azureVaultName;
		fLogger.info("azureVaultAddress : " + azureVaultAddress);
	}

	/**
	 * Resolve a credential.
	 */
	@Override
	public Map<String, String> resolve(Map<String, String> args) {

		String credId = (String) args.get(ARG_ID);
		String credType = (String) args.get(ARG_TYPE);
		fLogger.info("credId: " + credId);
		fLogger.info("credType: " + credType);
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

		if(credId == null || credType == null) {
			throw new RuntimeException("Invalid credential Id or type found.");
		}

		if (credType == "snmpv3") {
			snmpv3PrivacyCredId = (String) args.get(SNMPV3_ARG_PRIVACY_ID);
			if (snmpv3PrivacyCredId == null) {
				throw new RuntimeException("Invalid Privacy credential Id");
			}
		}

		// the resolved credential is returned in a HashMap...
		Map<String, String> result = new HashMap<String, String>();

		// Connect to vault and retrieve credential
		try {
			fLogger.info("Check if the Azure Environment Variables are set. This is mandatory for this integration to work");
			if (System.getenv("AZURE_CLIENT_ID") == null || System.getenv("AZURE_CLIENT_SECRET") == null || System.getenv("AZURE_TENANT_ID") == null) {
				fLogger.error("ENV AZURE_CLIENT_ID || AZURE_CLIENT_SECRET || AZURE_TENANT_ID is missing");
				throw new RuntimeException("AZURE Client Secrets are missing. Please set as System Environment Variables");
			}

			SecretClient secretClient;

			if (isProxyEnabled) {
				OkHttpClient newClient = getTrustAllCertsClient();
				HttpClient httpClient = new OkHttpAsyncHttpClientBuilder(newClient)
						.proxy(new ProxyOptions(ProxyOptions.Type.HTTP, new InetSocketAddress(getProxyHostProperty, getProxyPortProperty)))
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
		} 
		catch (RuntimeException e) {
			fLogger.error("### Unable to connect to Vault: " + azureVaultAddress, e);
			throw new RuntimeException("### Unable to connect to Vault: " + azureVaultAddress, e);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (KeyManagementException e) {
			throw new RuntimeException(e);
		}
		return result;
	}

	private static boolean isNullOrEmpty(String str) {
		if(str != null && !str.isEmpty())
			return false;
		return true;
	}

	private static void disableSSLCertificateVerification() {
		try {
			// Create a custom TrustManager that accepts all certificates
			TrustManager[] trustAllCerts = new TrustManager[] {
					new X509TrustManager() {
						public X509Certificate[] getAcceptedIssuers() {
							return null;
						}

						public void checkClientTrusted(X509Certificate[] certs, String authType) {
						}

						public void checkServerTrusted(X509Certificate[] certs, String authType) {
						}
					}
			};

			// Create an SSLContext with the custom TrustManager
			SSLContext sslContext = SSLContext.getInstance("TLS");
			sslContext.init(null, trustAllCerts, new SecureRandom());

			// Set the custom SSLContext as the default SSLContext
			HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
		} catch (NoSuchAlgorithmException | KeyManagementException e) {
			e.printStackTrace();
		}
	}

	public static OkHttpClient getTrustAllCertsClient() throws NoSuchAlgorithmException, KeyManagementException {
		TrustManager[] trustAllCerts = new TrustManager[]{
				new X509TrustManager() {
					@Override
					public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {
					}

					@Override
					public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {
					}

					@Override
					public java.security.cert.X509Certificate[] getAcceptedIssuers() {
						return new java.security.cert.X509Certificate[]{};
					}
				}
		};

		SSLContext sslContext = SSLContext.getInstance("SSL");
		sslContext.init(null, trustAllCerts, new java.security.SecureRandom());

		OkHttpClient.Builder newBuilder = new OkHttpClient.Builder();
		newBuilder.sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) trustAllCerts[0]);
		newBuilder.hostnameVerifier((hostname, session) -> true);
		newBuilder.protocols(Arrays.asList(Protocol.HTTP_1_1));
		return newBuilder.build();
	}

	private static boolean isNullOrEmptyMap(Map < ? , ? > map) {
		return (map == null || map.isEmpty());
	}
	
	/**
	 * Return the API version supported by this class.
	 * Note: should be less than 1.1 for external credential resolver.
	 */
	@Override
	public String getVersion() {
		return "0.1";
	}

	// main method to test locally, provide your vault details and test it.
	// TODO: Remove this before moving to production
//	public static void main(String[] args) {
//		CredentialResolver obj = new CredentialResolver();
//		// use your local details for testing.
//		obj.azureVaultName = "azurevaultname";
//		obj.azureVaultAddress = "https://xxx.vault.azure.net/";
//		obj.isProxyEnabled = true;
//		obj.getProxyHostProperty = "127.0.0.1";
//		obj.getProxyPortProperty = Integer.parseInt("8080");
//		Map<String, String> map = new HashMap<>();
//		String credId = "azurecredid";
//		String credType = "windows";
//		map.put(ARG_ID, credId);
//		map.put(ARG_TYPE, credType);
//		fLogger.info("result" + obj);
//		Map<String, String> result = obj.resolve(map);
//		System.out.println("Result: \n" + result.toString());
//	}
}