/*
 * Copyright IBM Corp. 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import ibm.security.internal.interfaces.MLKEMKey;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

class MLKEMKeyFactory extends KeyFactorySpi {

    private OpenJCEPlusProvider provider;
    private String algName = null;

    static MLKEMKey toMLKEMKey(OpenJCEPlusProvider provider, Key key) throws InvalidKeyException {
        return (MLKEMKey) (new MLKEMKeyFactory(provider, key.getAlgorithm())).engineTranslateKey(key);
    }

    private MLKEMKeyFactory(OpenJCEPlusProvider provider, String name) {
        this.provider = provider;
        this.algName = name;
    }

    /**
     * Check the strength of an MLKEM key to make sure it is not
     * too short or long.
     *
     * @param k
     *          the K parameter value which can only be 2, 3 or 4 currently.
     * 
     * @throws InvalidKeyException
     *                             if any of the values are unacceptable.
     */
    static void checkKeyLengths(int k) throws InvalidKeyException {

        if ((k > 4) || (k < 2)) {
            throw new InvalidKeyException(
                    "The K parameter value of a key must be 2, 3 or 4 only");
        }
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        try {
            if (keySpec instanceof PKCS8EncodedKeySpec) {
                PrivateKey generated = new MLKEMPrivateKey(provider,
                        ((PKCS8EncodedKeySpec) keySpec).getEncoded());
                checkKeyAlgo(generated);
                return generated;
            } else {
                throw new InvalidKeySpecException("Inappropriate key specification");
            }
        } catch (InvalidKeyException e) {
            throw new InvalidKeySpecException("Inappropriate key specification: " + e.getMessage());
        }
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        try {

            if (keySpec instanceof X509EncodedKeySpec) {
                MLKEMPublicKey generated = new MLKEMPublicKey(provider,
                        ((X509EncodedKeySpec) keySpec).getEncoded());
                checkKeyAlgo(generated);
                return generated;
            } else {
                throw new InvalidKeySpecException("Inappropriate key specification");
            }
        } catch (InvalidKeyException e) {
            throw new InvalidKeySpecException("Inappropriate key specification: " + e.getMessage());
        }
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
            throws InvalidKeySpecException {
        try {
            if (key instanceof com.ibm.crypto.plus.provider.MLKEMPublicKey) {
                // Determine valid key specs
                Class<?> x509KeySpec = Class.forName("java.security.spec.X509EncodedKeySpec");

                if (x509KeySpec.isAssignableFrom(keySpec)) {
                    return keySpec.cast(new X509EncodedKeySpec(key.getEncoded()));
                } else {
                    throw new InvalidKeySpecException("Inappropriate key specification");
                }
            } else if (key instanceof com.ibm.crypto.plus.provider.MLKEMPrivateKey) {
                // Determine valid key specs
                Class<?> pkcs8KeySpec = Class.forName("java.security.spec.PKCS8EncodedKeySpec");

                if (pkcs8KeySpec.isAssignableFrom(keySpec)) {
                    return keySpec.cast(new PKCS8EncodedKeySpec(key.getEncoded()));
                } else {
                    throw new InvalidKeySpecException("Inappropriate key specification");
                }

            } else {
                throw new InvalidKeySpecException("Inappropriate key type");
            }
        } catch (ClassNotFoundException | ClassCastException e) {
            throw new InvalidKeySpecException("Unsupported key specification: " + e.getMessage());
        }
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {

        if (key == null) {
            throw new InvalidKeyException("Key must not be null");
        }
        // ensure the key algorithm matches the current KeyFactory instance
        checkKeyAlgo(key);

        try {
            if (key instanceof java.security.PublicKey) {
                // Check if key originates from this factory
                if (key instanceof com.ibm.crypto.plus.provider.MLKEMPublicKey) {
                    return key;
                }
                // Convert key to spec
                X509EncodedKeySpec x509KeySpec = (X509EncodedKeySpec) engineGetKeySpec(key,
                        X509EncodedKeySpec.class);
                // Create key from spec, and return it
                return engineGeneratePublic(x509KeySpec);
            } else if (key instanceof com.ibm.crypto.plus.provider.MLKEMPrivateKey) {
                // Check if key originates from this factory
                if (key instanceof com.ibm.crypto.plus.provider.MLKEMPrivateKey) {
                    return key;
                }
                // Convert key to spec
                X509EncodedKeySpec x509KeySpec = (X509EncodedKeySpec) engineGetKeySpec(key,
                        X509EncodedKeySpec.class);
                // Create key from spec, and return it
                return engineGeneratePrivate(x509KeySpec);
            } else {
                throw new InvalidKeyException("Wrong algorithm type");
            }
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException("Cannot translate key: " + e.getMessage());
        }
    }

    // Internal utility method for checking key algorithm
    private void checkKeyAlgo(Key key) throws InvalidKeyException {
        String keyAlg = key.getAlgorithm();
        if (keyAlg == null) {
            // Thread.dumpStack();
            throw new InvalidKeyException("Expected a " + this.algName + " key, but got " + keyAlg);
        } else if (!key.getAlgorithm().equalsIgnoreCase(this.algName)) {
            throw new InvalidKeyException("Expected a " + this.algName + " key, but got " + keyAlg);
        }

    }

    public static final class MLKEM512 extends MLKEMKeyFactory {

        public MLKEM512(OpenJCEPlusProvider provider) {
            super(provider, "ML-KEM-512");
        }
    }

    public static final class MLKEM786 extends MLKEMKeyFactory {

        public MLKEM786(OpenJCEPlusProvider provider) {
            super(provider, "ML-KEM-786");
        }
    }

    public static final class MLKEM1024 extends MLKEMKeyFactory {

        public MLKEM1024(OpenJCEPlusProvider provider) {
            super(provider, "ML-KEM-1024");
        }
    }
}
