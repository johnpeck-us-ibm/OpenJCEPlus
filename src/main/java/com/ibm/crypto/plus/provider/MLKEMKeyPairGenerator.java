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
import com.ibm.crypto.plus.provider.ock.MLKEMKey;
import sun.security.x509.AlgorithmId;
import ibm.security.internal.spec.MLKEMParameterSpec;
import ibm.security.internal.interfaces.MLKEMKey;

abstract class RMLKEMKeyPairGenerator extends KeyPairGeneratorSpi {
    
    private MLKEMParameterSpec params = null;
    private OpenJCEPlusProvider provider = null;

    static int DEF_MLKEM_KEY_SIZE = 512;
    private MLKEMParameterSpec mlkemSpec = null;
    private AlgorithmId mlkemId;


    public MLKEMKeyPairGenerator(OpenJCEPlusProvider provider) {
        this.provider = provider;
        this.keysize = DEF_MLKEM_KEY_SIZE;
    }

    @Override
    public void initialize(int keysize, SecureRandom random) throws InvalidParameterException {
        this.keysize = keysize;
        this.mlkemSpec = null;
        this.oid = null;
        this.random = null; //OCKC defines the securerandom used and can not be specified on the fly.
    }

    /**
     * To-Do Currently we cannot generate curves based on parameters.
     */
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (!(params instanceof MLKEMParameterSpec)) {
                throw new InvalidAlgorithmParameterException(
                        "Params must be instance of MLEKMParameterSpec");
            }
        }

        this.mlkemSpec = (MLKEMParameterSpec) params;
        this.keysize = mlkemSpec.getKeySize();
        this.random = null; //OCKC defines the securerandom used and can not be specified on the fly.
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

  
}
