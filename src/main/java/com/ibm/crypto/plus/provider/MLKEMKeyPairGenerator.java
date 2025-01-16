/*
 * Copyright IBM Corp. 2024, 2025
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.OCKMLKEMKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

abstract class MLKEMKeyPairGenerator extends KeyPairGeneratorSpi {

    private OpenJCEPlusProvider provider = null;
    private String mlkemAlg;

    public MLKEMKeyPairGenerator(OpenJCEPlusProvider provider) {
        this.provider = provider;
        this.mlkemAlg = "ML_KEM_512";
    }

    public MLKEMKeyPairGenerator(OpenJCEPlusProvider provider, int keySize, String algName) {
        this.provider = provider;
        this.mlkemAlg = algName;
    }

    /**
     * Initialize based on parameters.
     */
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException(
                "Params not needed for ML_KEM keys");
    }

    @Override
    public KeyPair generateKeyPair() {
        try {
            OCKMLKEMKey mlkemKey = OCKMLKEMKey.generateKeyPair(provider.getOCKContext(), this.mlkemAlg);
            MLKEMPrivateKey privKey = new MLKEMPrivateKey(provider, mlkemKey);
            MLKEMPublicKey pubKey = new MLKEMPublicKey(provider, mlkemKey);
            return new KeyPair(pubKey, privKey);
        } catch (Exception e) {
            throw provider.providerException("Failure in generateKeyPair", e);
        }
    }

}
