package com.snc.discovery;

import java.util.*;
import java.io.*;


/**
 * Basic implementation of a CredentialResolver that uses a properties file.
 * This is invoked from CredentialResolver
 */

public class FileCredentialResolver extends CredentialResolver{
    public static final String FILE_PATH = "mid.external_credentials.file.path";
    private Properties fProps;

    private void loadProps(String propFilePath) {
        if(fProps == null)
            fProps = new Properties();
        try {
            File propFile = new File(propFilePath);
            if(!propFile.exists() || !propFile.canRead()) {
                System.err.println("Can't open "+propFile.getAbsolutePath());
            }
            else {
                InputStream propsIn = new FileInputStream(propFile);
                fProps.load(propsIn);
            }
        } catch (IOException e) {
            System.err.println("Problem loading credentials file:");
            e.printStackTrace();
        }
    }

    public Map fileCredResolve(String credId, String credType, String credsFile) throws IOException {

        String keyPrefix = credId+"."+credType+".";
//        credentialFile = CredentialResolver.getProperty.apply(FILE_PATH);
//
        if (credsFile == null || credsFile.equals("")) {
            throw new RuntimeException(String.format("MID server property %s is empty but required", credsFile));
        }

        fLogger.info("aaaa" + credsFile);
        loadProps(credsFile);

        // the resolved credential is returned in a HashMap...
        Map result = new HashMap();
        result.put(VAL_USER, fProps.get(keyPrefix + VAL_USER));
        result.put(VAL_PSWD, fProps.get(keyPrefix + VAL_PSWD));
        result.put(VAL_PKEY, fProps.get(keyPrefix + VAL_PKEY));
        result.put(VAL_PASSPHRASE, fProps.get(keyPrefix + VAL_PASSPHRASE));
        result.put(VAL_AUTHPROTO, fProps.get(keyPrefix + VAL_AUTHPROTO));
        result.put(VAL_AUTHKEY, fProps.get(keyPrefix + VAL_AUTHKEY));
        result.put(VAL_PRIVPROTO, fProps.get(keyPrefix + VAL_PRIVPROTO));
        result.put(VAL_PRIVKEY, fProps.get(keyPrefix + VAL_PRIVKEY));

//        fLogger.error("Error while resolving credential id/type["+credId+"/"+credType+"]");
//        throw new RuntimeException("Error while resolving credential id/type["+credId+"/"+credType+"]");
        return result;
    }
}