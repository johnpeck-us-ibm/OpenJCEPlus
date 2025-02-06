/*
 * Copyright IBM Corp. 2025
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.base;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class BaseTestPQCKeys extends BaseTestJunit5 {


    protected KeyPairGenerator pqcKeyPairGen;
    protected KeyFactory pqcKeyFactory;

    @BeforeEach
    public void setUp() throws Exception {
        pqcKeyPairGen = KeyPairGenerator.getInstance(getAlgorithm(), getProviderName());
        pqcKeyFactory = KeyFactory.getInstance(getAlgorithm(), getProviderName());
    }

    @Test
    public void testPQCKeyGen() throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not support PQC keys currently
            return;
        }
        KeyPair pqcKeyPair = generateKeyPair();
        pqcKeyPair.getPublic();
        pqcKeyPair.getPrivate();
    }

    @Test
    public void testPQCKeyFactoryCreateFromEncoded() throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not support PQC keys currently
            return;
        }
        keyFactoryCreateFromEncoded();
    }

    @Test

    protected KeyPair generateKeyPair() throws Exception {
        KeyPair keyPair = pqcKeyPairGen.generateKeyPair();
        if (keyPair.getPrivate() == null) {
            fail("RSA Private key is null");
        }

        if (keyPair.getPublic() == null) {
            fail("RSA Public key is null");
        }

        if (!(keyPair.getPrivate() instanceof PrivateKey)) {
            fail("Private key is not a RSAPrivateKey");
        }

        if (!(keyPair.getPublic() instanceof PublicKey)) {
            fail("Private key is not a RSAPublicKey");
        }

        return keyPair;
    }


    protected void keyFactoryCreateFromEncoded() throws Exception {

        KeyPair pqcKeyPair = generateKeyPair();

        X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(pqcKeyPair.getPublic().getEncoded());
        PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(
                pqcKeyPair.getPrivate().getEncoded());

        PublicKey rsaPub =  pqcKeyFactory.generatePublic(x509Spec);
        PrivateKey rsaPriv =  pqcKeyFactory.generatePrivate(pkcs8Spec);

        if (!Arrays.equals(rsaPub.getEncoded(), pqcKeyPair.getPublic().getEncoded())) {
            fail("RSA public key does not match generated public key");
        }

        if (!Arrays.equals(rsaPriv.getEncoded(), pqcKeyPair.getPrivate().getEncoded())) {
            fail("RSA private key does not match generated public key");
        }
    }
}

