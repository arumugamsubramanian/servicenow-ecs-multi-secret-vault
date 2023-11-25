package com.snc.discovery;

import java.util.HashMap;
import java.util.Map;

import com.service_now.mid.services.Config;
import com.snc.automation_common.integration.creds.IExternalCredential;
import com.snc.core_automation_common.logging.Logger;
import com.snc.core_automation_common.logging.LoggerFactory;
import com.snc.discovery.azureKeyVault.AzureKeyVaultCredentialResolver;
import com.snc.discovery.fileVault.FileCredentialResolver;
import com.snc.discovery.hashicorpVault.HashicorpVaultCredentialResolver;

import java.io.IOException;
import java.util.function.Function;

import static com.snc.discovery.azureKeyVault.AzureKeyVaultCredentialResolver.*;
import static com.snc.discovery.fileVault.FileCredentialResolver.FILE_PATH;
import static com.snc.discovery.hashicorpVault.HashicorpVaultCredentialResolver.PROP_ADDRESS;
import static com.snc.discovery.hashicorpVault.HashicorpVaultCredentialResolver.PROP_CA;
import static com.snc.discovery.hashicorpVault.HashicorpVaultCredentialResolver.PROP_TLS_SKIP_VERIFY;
import static com.snc.discovery.hashicorpVault.HashicorpVaultCredentialResolver.*;

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
//	hashicorp vault
	private String vaultAddress;
	private String vaultCA;
	private String tlsSkipVerifyRaw;
	private String masterToken;

	private String vaultUser;
	private String vaultPass;
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
//		hashicorp vault
		vaultAddress = configMap.get(PROP_ADDRESS);
		vaultCA = configMap.get(PROP_CA);
		tlsSkipVerifyRaw = configMap.get(PROP_TLS_SKIP_VERIFY);
		vaultUser = configMap.get(PROP_VAULT_USERNAME);
		vaultPass = configMap.get(PROP_VAULT_PASSWORD);
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
		} else if (isHashicorpVaultMatchingPattern(credId)) {
			HashicorpVaultCredentialResolver hv = new HashicorpVaultCredentialResolver();
			try{
				result = hv.resolve(args, vaultAddress, vaultCA, tlsSkipVerifyRaw, vaultUser, vaultPass);
				return result;
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		} else {
			fLogger.info("No matching secret vault provider found, please reach out to https://github.com/arumugamsubramanian for implementation");
		}
		return result;
	}


	private static boolean isHashicorpVaultMatchingPattern(String input) {
		// Check if the string starts with "hv/" and has additional characters
		return input.startsWith("hv/") && input.length() > "hv/".length();
	}

	static public boolean isNullOrEmpty(String str) {
		if(str != null && !str.isEmpty())
			return false;
		return true;
	}



	static public boolean isNullOrEmptyMap(Map<?, ?> map) {
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
////		obj.credentialFile = "/servicenow-ecs-multi-secret-vault/test/creds.properties";
//		obj.vaultAddress = "http://127.0.0.1:8200";
////		obj.vaultCA = getProperty.apply(PROP_CA);
//		obj.tlsSkipVerifyRaw = String.valueOf(true);
////		obj.masterToken = "hvs.yxS5OatpCK6gG9tGusLZooXA";
//		obj.vaultUser = "servicenow";
//		obj.vaultPass = "servicenow";
//		// use your local details for testing.
////		obj.azureVaultName = "azurevaultname";
////		obj.azureVaultAddress = "https://xxx.vault.azure.net/";
////		obj.azureIsProxyEnabled = true;
////		obj.azureProxyHostProperty = "127.0.0.1";
////		obj.azureProxyPortProperty = Integer.parseInt("8080");
//		Map<String, String> map = new HashMap<>();
////		vault_type.cred ID from ServiceNow.cred type
//		String credId = "hv/secret/data/linux";
//		String credType = "ssh_password";
//		map.put(ARG_ID, credId);
//		map.put(ARG_TYPE, credType);
//		fLogger.info("result" + obj);
//		Map<String, String> result = obj.resolve(map);
//		System.out.println("Result: \n" + result.toString());
//	}
}