package com.snc.discovery;

import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import com.azure.core.http.okhttp.OkHttpAsyncHttpClientBuilder;
import com.azure.identity.EnvironmentCredentialBuilder;
import com.service_now.mid.services.Config;
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
import java.util.function.Function;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import javax.net.ssl.*;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import com.azure.identity.ClientSecretCredential;
import com.azure.identity.*;
import com.azure.core.credential.TokenCredential;
import com.azure.core.credential.TokenCredential;
import java.util.Arrays;
import java.util.Collections;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;

import static com.snc.discovery.AzureKeyVaultCredentialResolver.*;
import static com.snc.discovery.FileCredentialResolver.FILE_PATH;

/**
 * Custom External Credential Resolver for Azure credential vault.
 */
public class CredentialResolver implements IExternalCredential{

//	extend the permissible names of arguments passed INTO the resolve()
	public static final String AZURE_SECRET_KEY = "secret_key";
	public static final String AZURE_CLIENT_ID = "client_id";
	public static final String AZURE_TENANT_ID = "tenant_id";
//	public static final String AWS_ACCESS_KEY = "AWSServiceAccount.aws.user";
//	public static final String AWS_SECRET_KEY = "AWSServiceAccount.aws.pswd";
	public static final String SNMPV3_ARG_PRIVACY_ID = "privacy_credential_id";
	public static final String SNMPV3_AUTHENTICATION_PROTOCOL = "authentication_protocol";
	public static final String SNMPV3_AUTHENTICATION_KEY = "authentication_key";
	public static final String SNMPV3_PRIVACY_PROTOCOL = "privacy_protocol";
	public static final String SNMPV3_PRIVACY_KEY = "privacy_key";

	//	starts here
//	public static final String AZURE_KEY_VAULT_NAME_PROPERTY = "ext.cred.azure.vault.name";
//	public static final String PROXY_HOST_PROPERTY = "ext.cred.azure.vault.proxy.host";
//	public static final String PROXY_PORT_PROPERTY = "ext.cred.azure.vault.proxy.port";

//	=================================================
//	AKV
	private String azureVaultAddress;
	private String azureVaultName;
	private String azureProxyHostProperty;
	private int azureProxyPortProperty;
	private boolean azureIsProxyEnabled;
//	=================================================
//	File vault
	private String credentialFile;
//	=================================================
	// Logger object to log messages in agent.log
	public static final Logger fLogger = LoggerFactory.getLogger(CredentialResolver.class);
	public static Function<String, String> getProperty = null;
	public CredentialResolver() {
		getProperty = prop -> Config.get().getProperty(prop);
	}
	public CredentialResolver(Function<String, String> getProperty) {
		this.getProperty = getProperty;
	}
	
	/**
	 * Config method with preloaded config parameters from config.xml.
	 * @param configMap - contains config parameters with prefix "ext.cred" only.
	 */
	@Override
	public void config(Map<String, String> configMap) {
		//Note: To load config parameters from MID config.xml if not available in configMap.
		//propValue = Config.get().getProperty("<Parameter Name>")
//==================================================================================================================
//		File based secret vault midserver configuration parameters from config.xml
		credentialFile = configMap.get(FILE_PATH);
//==================================================================================================================
//		Azure Key Vault midserver configuration parameters from config.xml
		azureVaultName = configMap.get(AZURE_KEY_VAULT_NAME_PROPERTY);
//		If porxy is required for AKV
		azureIsProxyEnabled = !(isNullOrEmpty(configMap.get(PROXY_HOST_PROPERTY)) && isNullOrEmpty(configMap.get(PROXY_PORT_PROPERTY)));
//		fLogger.info("Using Proxy Host : " + configMap.get(PROXY_HOST_PROPERTY));
//		fLogger.info("Using Proxy Port : " + configMap.get(PROXY_PORT_PROPERTY));
//		fLogger.info("Proxy enabled : " + azureIsProxyEnabled);
		if (azureIsProxyEnabled) {
			azureProxyHostProperty = configMap.get(PROXY_HOST_PROPERTY);
			azureProxyPortProperty = Integer.parseInt(configMap.get(PROXY_PORT_PROPERTY));
		}
//		fLogger.info("azureVaultName : " + azureVaultName);
//		if(isNullOrEmpty(azureVaultName))
//			fLogger.error("[Vault] INFO - CredentialResolver " + AZURE_KEY_VAULT_NAME_PROPERTY + " not set!");
		azureVaultAddress = "https://" + azureVaultName;
//		fLogger.info("azureVaultAddress : " + azureVaultAddress);
//==================================================================================================================
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
////		windows, linux, unix creds
//		String username = "";
//		String password = "";
//		String passphrase = "";
//		String private_key = "";
////		azure creds
//		String azureClientId = "";
//		String azureTenantId = "";
//		String azureSecretKey = "";
//// 		aws creds
//		String awsAccessKey = "";
//		String awsSecretKey = "";
////		snmpv3
//		String snmpv3PrivacyCredId = null;
//		Map<String, String> snmpv3PrivacyKeyTags = new HashMap<>();
//		String snmpv3AuthProtocol = "";
//		String snmpv3AuthKey = "";
//		String snmpv3PrivacyProtocol = "";
//		String snmpv3PrivacyKey = "";
//		KeyVaultSecret snmpv3PrivacyCredSecret = null;

//		Map<String, String> tags = new HashMap<>();

		if(credId == null || credType == null) {
			throw new RuntimeException("Empty credential Id or type found.");
		}

		if (credType == "snmpv3") {
//			snmpv3PrivacyCredId = (String) args.get(SNMPV3_ARG_PRIVACY_ID);
			if ((String) args.get(SNMPV3_ARG_PRIVACY_ID) == null) {
				throw new RuntimeException("Empty Privacy credential Id");
			}
		}

		// the resolved credential is returned in a HashMap...
		Map<String, String> result = new HashMap<String, String>();

		if (credId.startsWith("file")) {
			FileCredentialResolver fileObject = new FileCredentialResolver();
			try {
				result = fileObject.fileCredResolve(credId, credType, credentialFile);
				return result;
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		} else if (credId.startsWith("akv")) {
			AzureKeyVaultCredentialResolver akv = new AzureKeyVaultCredentialResolver();
			try {
				result = akv.azureKeyVaultCredResolve(credId, credType, azureVaultAddress, azureProxyHostProperty, azureProxyPortProperty, azureIsProxyEnabled);
				return result;
			} catch (IOException e){
				throw new RuntimeException(e);
			}
		}
		return result;
	}

	static boolean isNullOrEmpty(String str) {
		if(str != null && !str.isEmpty())
			return false;
		return true;
	}

//	private static void disableSSLCertificateVerification() {
//		try {
//			// Create a custom TrustManager that accepts all certificates
//			TrustManager[] trustAllCerts = new TrustManager[] {
//					new X509TrustManager() {
//						public X509Certificate[] getAcceptedIssuers() {
//							return null;
//						}
//
//						public void checkClientTrusted(X509Certificate[] certs, String authType) {
//						}
//
//						public void checkServerTrusted(X509Certificate[] certs, String authType) {
//						}
//					}
//			};
//
//			// Create an SSLContext with the custom TrustManager
//			SSLContext sslContext = SSLContext.getInstance("TLS");
//			sslContext.init(null, trustAllCerts, new SecureRandom());
//
//			// Set the custom SSLContext as the default SSLContext
//			HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
//		} catch (NoSuchAlgorithmException | KeyManagementException e) {
//			e.printStackTrace();
//		}
//	}

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

	static boolean isNullOrEmptyMap(Map<?, ?> map) {
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
//		obj.credentialFile = "/servicenow-ecs-multi-secret-vault/test/creds.properties";
//		// use your local details for testing.
////		obj.azureVaultName = "azurevaultname";
////		obj.azureVaultAddress = "https://xxx.vault.azure.net/";
////		obj.azureIsProxyEnabled = true;
////		obj.azureProxyHostProperty = "127.0.0.1";
////		obj.azureProxyPortProperty = Integer.parseInt("8080");
//		Map<String, String> map = new HashMap<>();
////		vault_type.cred ID from ServiceNow.cred type
//		String credId = "filevault-linux";
//		String credType = "ssh_password";
//		map.put(ARG_ID, credId);
//		map.put(ARG_TYPE, credType);
//		fLogger.info("result" + obj);
//		Map<String, String> result = obj.resolve(map);
//		System.out.println("Result: \n" + result.toString());
//	}
}