/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

public class BaseTestPQCSignature extends BaseTestJunit5Signature {


    static final byte[] origMsg = "this is the original message to be signed".getBytes();

    @ParameterizedTest
    @CsvSource({"ML_DSA_44","ML-DSA-65","ML_DSA_87",
        "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f","SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f","SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f",
        "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f","SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f","SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"})
    public void testPQCKeySignature(String Algorithm) throws Exception {

        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not supported
            return;
        }

        try { 
            KeyPair keyPair = generateKeyPair(Algorithm);
            doSignVerify(Algorithm, origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (Exception e) {
            throw new Exception(e.getCause() +" - "+Algorithm, e);
        }
    }

    protected KeyPair generateKeyPair(String Algorithm) throws Exception {
        KeyPairGenerator pqcKeyPairGen = KeyPairGenerator.getInstance(Algorithm, getProviderName());

        return pqcKeyPairGen.generateKeyPair();
    }

}

