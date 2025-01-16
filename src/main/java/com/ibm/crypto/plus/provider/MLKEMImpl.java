/*
 * Copyright IBM Corp. 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.OCKException;
import com.ibm.crypto.plus.provider.ock.OCKKEM;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class MLKEMImpl implements KEMSpi {
    OpenJCEPlusProvider provider;

    public MLKEMImpl(OpenJCEPlusProvider provider) {
        if (!OpenJCEPlusProvider.verifySelfIntegrity(this)) {
            throw new SecurityException("Integrity check failed for: " + provider.getName());
        }

        this.provider = provider;
    }

    /**
     * spec - The AlgorithmParameterSpec is not used and should be null. If not null
     * it will be ignored.
     * secureRandom - This parameter is not used and should be null. If not null it
     * will be ignored.
     */
    @Override
    public KEMSpi.EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey,
            AlgorithmParameterSpec spec, SecureRandom secureRandom)
            throws InvalidAlgorithmParameterException, InvalidKeyException {
        if (!(publicKey instanceof MLKEMPublicKey)) {
            throw new InvalidKeyException("unsupported key");
        }

        return new MLKEMEncapsulator(publicKey, spec, null);
    }

    class MLKEMEncapsulator implements KEMSpi.EncapsulatorSpi {

        PublicKey publicKey;
        int size = 0;

        /**
         * spec - The AlgorithmParameterSpec is not used and should be null. If not null
         * it will be ignored.
         * secureRandom - This parameter is not used and should be null. If not null it
         * will be ignored.
         */
        MLKEMEncapsulator(PublicKey publicKey, AlgorithmParameterSpec spec,
                SecureRandom secureRandom) {
            this.publicKey = publicKey;
        }

        @Override
        public KEM.Encapsulated engineEncapsulate(int from, int to, String algorithm) {
            byte[] encapsulation = null;
            byte[] secret = null;
            try {
                OCKKEM.OCKKEM_encapsulate(provider.getOCKContext(), publicKey.getEncoded(), encapsulation, secret);
            } catch (OCKException e) {
                return null;
            }

            this.size = to - from + 1;
            return new KEM.Encapsulated(
                    new SecretKeySpec(secret, from, this.size - 1, algorithm),
                    encapsulation, null);
        }

        @Override
        public int engineEncapsulationSize() {
            return 0; // needs to be based on the k of the key.
        }

        @Override
        public int engineSecretSize() {
            return this.size;
        }
    }

    /**
     * spec - The AlgorithmParameterSpec is not used and should be null. If not null
     * it will be ignored.
     */
    @Override
    public KEMSpi.DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey,
            AlgorithmParameterSpec spec)
            throws InvalidAlgorithmParameterException, InvalidKeyException {
        if (!(privateKey instanceof MLKEMPrivateKey)) {
            throw new InvalidKeyException("unsupported key");
        }

        return new MLKEMDecapsulator(privateKey, null);
    }

    /**
     * spec - The AlgorithmParameterSpec is not used and should be null. If not null
     * it will be ignored.
     */
    class MLKEMDecapsulator implements KEMSpi.DecapsulatorSpi {
        PrivateKey privateKey;
        int size = 0;

        MLKEMDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec) {
            this.privateKey = privateKey;
        }

        @Override
        public SecretKey engineDecapsulate(byte[] cipherText, int from, int to, String algorithm)
                throws DecapsulateException {
            byte[] secret;

            try {
                secret = OCKKEM.OCKKEM_decapsulate(provider.getOCKContext(), this.privateKey.getEncoded(), cipherText);
            } catch (OCKException e) {
                throw new DecapsulateException(e.getMessage());
            }

            size = to - from + 1;
            return new SecretKeySpec(secret, from, size - 1, algorithm);
        }

        @Override
        public int engineEncapsulationSize() {

            return 0; // Needs to be calculated from k of key
        }

        @Override
        public int engineSecretSize() {

            return this.size;
        }
    }
}
