/*
 * Copyright IBM Corp. 2024, 2025
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.OCKPQCKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

abstract class PQCKeyPairGenerator extends KeyPairGeneratorSpi {

    private OpenJCEPlusProvider provider = null;
    private String mlkemAlg;

    public PQCKeyPairGenerator(OpenJCEPlusProvider provider) {
        this.provider = provider;
    }

    public PQCKeyPairGenerator(OpenJCEPlusProvider provider, String algName) {
        this.provider = provider;
        this.mlkemAlg = algName;
    }

    /**
     * Initialize based on parameters.
     */
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException(
                "Params not needed.");
    }
    @Override
    public void initialize(int keysize, SecureRandom random) {
        if (keysize != -1) {
            // User can call initialize(-1, sr) to provide a SecureRandom
            // without touching the parameter set currently used
            throw new InvalidParameterException("keysize not supported");
        }
        // This functions is here for compatablity with Oracle and Spi
        // However, since OCKC does not allow specification of Random
        // this function does nothing.
    }

    @Override
    public KeyPair generateKeyPair() {
        try {
            OCKPQCKey mlkemKey = OCKPQCKey.generateKeyPair(provider.getOCKContext(), this.mlkemAlg);
            PQCPrivateKey privKey = new PQCPrivateKey(provider, mlkemKey);
            PQCPublicKey pubKey = new PQCPublicKey(provider, mlkemKey);
            return new KeyPair(pubKey, privKey);
        } catch (Exception e) {
            throw provider.providerException("Failure in generateKeyPair", e);
        }
    }
    public static final class MLKEM512 extends PQCKeyPairGenerator {

        public MLKEM512(OpenJCEPlusProvider provider) {
            super(provider, "ML-KEM-512");
        }
    }

    public static final class MLKEM786 extends PQCKeyPairGenerator {

        public MLKEM786(OpenJCEPlusProvider provider) {
            super(provider, "ML-KEM-786");
        }
    }

    public static final class MLKEM1024 extends PQCKeyPairGenerator {

        public MLKEM1024(OpenJCEPlusProvider provider) {
            super(provider, "ML-KEM-1024");
        }
    }
    public static final class MLDSA44 extends PQCKeyPairGenerator {

        public MLDSA44(OpenJCEPlusProvider provider) {
            super(provider, "ML-DSA-44");
        }
    }
    public static final class MLDSA65 extends PQCKeyPairGenerator {

        public MLDSA65(OpenJCEPlusProvider provider) {
            super(provider, "ML-DSA-65");
        }
    }
    public static final class MLDSA87 extends PQCKeyPairGenerator {

        public MLDSA87(OpenJCEPlusProvider provider) {
            super(provider, "ML-DSA-87");
        }
    }
    public static final class SLHDSASHA2128s extends PQCKeyPairGenerator {

        public SLHDSASHA2128s(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHA2-128s");
        }
    }
    public static final class SLHDSASHAKE128s extends PQCKeyPairGenerator {

        public SLHDSASHAKE128s(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHAKE-128s");
        }
    }
    public static final class SLHDSASHA2128f extends PQCKeyPairGenerator {

        public SLHDSASHA2128f(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHA2-128f");
        }
    }
    public static final class SLHDSASHAKE128f extends PQCKeyPairGenerator {

        public SLHDSASHAKE128f(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHAKE-128f");
        }
    }
    public static final class SLHDSASHA2192s extends PQCKeyPairGenerator {

        public SLHDSASHA2192s(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHA2-192s");
        }
    }
    public static final class SLHDSASHAKE192s extends PQCKeyPairGenerator {

        public SLHDSASHAKE192s(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHAKE-192s");
        }
    }
    public static final class SLHDSASHA2192f extends PQCKeyPairGenerator {

        public SLHDSASHA2192f(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHA2-192f");
        }
    }
    public static final class SLHDSASHAKE192f extends PQCKeyPairGenerator {

        public SLHDSASHAKE192f(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHAKE-192f");
        }
    }
    public static final class SLHDSASHA2256s extends PQCKeyPairGenerator {

        public SLHDSASHA2256s(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHA2-256s");
        }
    }
    public static final class SLHDSASHAKE256s extends PQCKeyPairGenerator {

        public SLHDSASHAKE256s(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHAKE-256s");
        }
    }
    public static final class SLHDSASHA2256f extends PQCKeyPairGenerator {

        public SLHDSASHA2256f(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHA2-256f");
        }
    }
    public static final class SLHDSASHAKE256f extends PQCKeyPairGenerator {

        public SLHDSASHAKE256f(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHAKE-256f");
        }
    }
}
