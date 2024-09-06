/*
 * Copyright IBM Corp. 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import com.ibm.crypto.plus.provider.ock.OCKMLKEMKey;
import sun.security.x509.AlgorithmId;
import ibm.security.internal.spec.MLKEMParameterSpec;
import ibm.security.internal.interfaces.MLKEMKey;

abstract class RMLKEMKeyPairGenerator extends KeyPairGeneratorSpi {
    
    private MLKEMParameterSpec params = null;
    private OpenJCEPlusProvider provider = null;

    static int DEF_MLKEM_KEY_SIZE = 512;
    private MLKEMParameterSpec mlkemSpec = null;
    private String mlkemAlg;
    private int keysize = 0;


    public MLKEMKeyPairGenerator(OpenJCEPlusProvider provider) {
        this.provider = provider;
        this.keysize = DEF_MLKEM_KEY_SIZE;
        this.mlkemAlg = "ML_KEM_512";
    }

    public MLKEMKeyPairGenerator(OpenJCEPlusProvider provider, int keySize, String algName) {
        this.provider = provider;
        this.keysize = keySize;
        this.mlkemAlg = algName;
    }

    @Override
    public void initialize(int keySize, SecureRandom random) throws InvalidParameterException {
        //Key size is determined by the algorithm.
        if (this.keysize != keySize) {
            throw new InvalidParameterException("Key size does not match algorithm.");
        }
        this.keysize = keySize;
        this.mlkemSpec = null;
    }

    /**
     * Initialize based on parameters.
     */
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (!(params instanceof MLKEMParameterSpec)) {
                throw new InvalidAlgorithmParameterException(
                        "Params must be instance of MLEKMParameterSpec");
            }
        }

        this.mlkemSpec = (MLKEMParameterSpec) params;
        if (this.keysize != mlkemSpec.getKeySize()) {
            throw new InvalidAlgorithmParameterException("Parameters do not match algorithm.");
        }
    }


    @Override
    public KeyPair generateKeyPair() {
        try {
            MLKEMKey mlkemKey = MLKEMKey.generateKeyPair(provider.getOCKContext(), this.keysize);
            MLKEMPrivateKey privKey = new MLKEMPrivateKey(provider, mlkemKey);
            MLKEMPublicKey pubKey = new RSAPublicKey(provider, mlkemKey);
            return new KeyPair(pubKey, privKey);
        } catch (Exception e) {
            throw provider.providerException("Failure in generateKeyPair", e);
        }
    }
    private String getAlgName(int keySize) {
        String result = null;
        switch (keySize) {
            case 512:
                result = "ML_KEM_512";
                break;
            case 768:
                result = "ML_KEM_786";
                break;
            case 1024:
                result = "ML_KEM_1024";
                break;
            default:
                //Not sure how we got here. But will default to 512
                result = "ML_KEM_512";
                break;

        return result;
    }

  
}
