/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.base;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class BaseTestRSASignatureInterop extends BaseTestSignatureInterop {

    //--------------------------------------------------------------------------
    //
    //
    static final byte[] origMsg = "this is the original message to be signed I changed to a very long message to make sure enough bytes are there for copying."
            .getBytes();
    int keySize = 1024;

    //--------------------------------------------------------------------------
    //
    //


    //--------------------------------------------------------------------------
    //
    //
    public BaseTestRSASignatureInterop(String providerName, String interopProviderName) {
        super(providerName, interopProviderName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public BaseTestRSASignatureInterop(String providerName, String interopProviderName,
            int keySize) {
        super(providerName, interopProviderName);
        this.keySize = keySize;
    }

    //--------------------------------------------------------------------------
    //
    //
    public void setUp() throws Exception {}

    //--------------------------------------------------------------------------
    //
    //
    public void tearDown() throws Exception {}

    //--------------------------------------------------------------------------
    //
    //
    public void testSHA1withRSA() throws Exception {
        if (providerName.equals("OpenJCEPlusFIPS")) {
            //FIPS does not support SHA1
            return;
        }
        KeyPair keyPair = generateKeyPair(this.keySize);
        doSignVerify("SHA1withRSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSHA224withRSA() throws Exception {
        KeyPair keyPair = generateKeyPair(this.keySize);
        doSignVerify("SHA224withRSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSHA256withRSA() throws Exception {
        KeyPair keyPair = generateKeyPair(this.keySize);
        doSignVerify("SHA256withRSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSHA384withRSA() throws Exception {
        KeyPair keyPair = generateKeyPair(this.keySize);
        doSignVerify("SHA384withRSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSHA512withRSA() throws Exception {
        KeyPair keyPair = generateKeyPair(this.keySize);
        doSignVerify("SHA512withRSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    //--------------------------------------------------------------------------
    //
    //
    /*
    RSAforSSL is not supported in other cryptographic providers in order to do interopt testing
    
    public void testRSAforSSL_hash1() throws Exception {
        KeyPair keyPair = generateKeyPair( this.keySize);
        byte[]  sslHash = Arrays.copyOf(origMsg, 1);
        doSignVerify("RSAforSSL", sslHash, keyPair.getPrivate(), keyPair.getPublic());
    }
    
    //--------------------------------------------------------------------------
    //
    //
    public void testRSAforSSL_hash5() throws Exception {
        KeyPair keyPair = generateKeyPair( this.keySize);
        byte[]  sslHash = Arrays.copyOf(origMsg, 5);
        doSignVerify("RSAforSSL", sslHash, keyPair.getPrivate(), keyPair.getPublic());
    }
    
    //--------------------------------------------------------------------------
    //
    //
    public void testRSAforSSL_hash20() throws Exception {
        KeyPair keyPair = generateKeyPair( this.keySize);
        byte[]  sslHash = Arrays.copyOf(origMsg, 20);
        doSignVerify("RSAforSSL", sslHash, keyPair.getPrivate(), keyPair.getPublic());
    }
     
    //--------------------------------------------------------------------------
    //
    //
    public void testRSAforSSL_hash36() throws Exception {
        KeyPair keyPair = generateKeyPair( this.keySize);
        byte[]  sslHash = Arrays.copyOf(origMsg, 36);
        doSignVerify("RSAforSSL", sslHash, keyPair.getPrivate(), keyPair.getPublic());
    }
    
    //--------------------------------------------------------------------------
    //
    //
    public void testRSAforSSL_hash40() throws Exception {
        KeyPair keyPair = generateKeyPair(this.keySize);
        byte[]  sslHash = Arrays.copyOf(origMsg, 40);
        doSignVerify("RSAforSSL", sslHash, keyPair.getPrivate(), keyPair.getPublic());
    }
    */
    //--------------------------------------------------------------------------
    //
    //
    protected KeyPair generateKeyPair(int keysize) throws Exception {
        KeyPairGenerator rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", providerName);
        rsaKeyPairGen.initialize(keysize);
        return rsaKeyPairGen.generateKeyPair();
    }
}

