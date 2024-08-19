/*
 * Copyright IBM Corp. 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import java.math.BigInteger;
import java.security.AccessController;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.ProviderException;
import java.security.PublicKey;
import ibm.security.internal.interfaces.MLKEMKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import ibm.security.internal.spec.MLKEMPrivateKeySpec;
import ibm.security.internal.spec.MLKEMPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.List;


class MLKEMKeyFactory extends KeyFactorySpi {

    private OpenJCEPlusProvider provider;
    private KeyType type = KeyType.MLKEM;


    public static RSAKeyFactory getInstance(OpenJCEPlusProvider provider, KeyType type) {
        return new RSAKeyFactory(provider, type);
    }

    static RSAKey toMLKEMKey(OpenJCEPlusProvider provider, Key key) throws InvalidKeyException {
        // FIXME
        // PKCS11 returns keys that extend MLKEMPrivateKey

        KeyType type = KeyType.lookup(key.getAlgorithm());

        return (MLKEMKey) new MLKEMKeyFactory(provider, type).engineTranslateKey(key);
    }

    /**
     * Check the strength of an MLKEM key to make sure it is not
     * too short or long. 
     *
     * @param k
     *            the K parameter value which can only be 2, 3 or 4 currently.

     * @throws InvalidKeyException
     *             if any of the values are unacceptable.
     */
    static void checkKeyLengths(int k) throws InvalidKeyException {

        if ((k > 4) || (k < 2)) {
            throw new InvalidKeyException(
                    "The K parameter value of a key must be 2, 3 or 4 only");
        }
    }

    public RSAKeyFactory(OpenJCEPlusProvider provider) {
        this.provider = provider;
        this.type = KeyType.MLKEM;
    }

    public RSAKeyFactory(OpenJCEPlusProvider provider, KeyType type) {
        this.provider = provider;
        this.type = type;
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        try {
            if (keySpec instanceof PKCS8EncodedKeySpec) {
                java.security.interfaces.MLKEMPrivateKey generated = MLKEMPrivateKey.newKey(provider,
                        ((PKCS8EncodedKeySpec) keySpec).getEncoded());
                checkKeyAlgo(generated, type.keyAlgo());
                return generated;

            } else if (keySpec instanceof MLKEMPrivateKeySpec) {

                MLKEMPrivateKeySpec mlkemSpec = (MLKEMPrivateKeySpec) keySpec;
                try {
                    return new MLEMPrivateKey(
                            RSAUtil.createAlgorithmId(this.type, rSpec.getParams()), provider,
                            rSpec.getModulus(), rSpec.getPublicExponent(),
                            rSpec.getPrivateExponent(), rSpec.getPrimeP(), rSpec.getPrimeQ(),
                            rSpec.getPrimeExponentP(), rSpec.getPrimeExponentQ(),
                            rSpec.getCrtCoefficient());
                } catch (ProviderException e) {
                    throw new InvalidKeySpecException(e);
                }
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
            if (keySpec instanceof RSAPublicKeySpec) {
                RSAPublicKeySpec rsaPubKeySpec = (RSAPublicKeySpec) keySpec;
                try {
                    return new RSAPublicKey(
                            RSAUtil.createAlgorithmId(this.type, rsaPubKeySpec.getParams()),
                            provider, rsaPubKeySpec.getModulus(),
                            rsaPubKeySpec.getPublicExponent());
                } catch (ProviderException e) {
                    throw new InvalidKeySpecException(e);
                }
            } else if (keySpec instanceof X509EncodedKeySpec) {
                java.security.interfaces.RSAPublicKey generated = new RSAPublicKey(provider,
                        ((X509EncodedKeySpec) keySpec).getEncoded());
                checkKeyAlgo(generated, type.keyAlgo());
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
            if (key instanceof java.security.interfaces.RSAPublicKey) {
                // Determine valid key specs
                Class<?> rsaPubKeySpec = Class.forName("java.security.spec.RSAPublicKeySpec");
                Class<?> x509KeySpec = Class.forName("java.security.spec.X509EncodedKeySpec");
                if (rsaPubKeySpec.isAssignableFrom(keySpec)) {
                    java.security.interfaces.RSAPublicKey rsaPubKey = (java.security.interfaces.RSAPublicKey) key;
                    return keySpec.cast(new RSAPublicKeySpec(rsaPubKey.getModulus(),
                            rsaPubKey.getPublicExponent(), rsaPubKey.getParams()));
                } else if (x509KeySpec.isAssignableFrom(keySpec)) {
                    return keySpec.cast(new X509EncodedKeySpec(key.getEncoded()));
                } else {
                    throw new InvalidKeySpecException("Inappropriate key specification");
                }
            } else if (key instanceof java.security.interfaces.RSAPrivateCrtKey) {
                // Determine valid key specs
                Class<?> rsaPrivKeySpec = Class.forName("java.security.spec.RSAPrivateKeySpec");
                Class<?> pkcs8KeySpec = Class.forName("java.security.spec.PKCS8EncodedKeySpec");
                if (keySpec.isAssignableFrom(RSAPrivateCrtKeySpec.class)) {
                    java.security.interfaces.RSAPrivateCrtKey rsaPrivCrtKey = (java.security.interfaces.RSAPrivateCrtKey) key;
                    return keySpec.cast(new RSAPrivateCrtKeySpec(rsaPrivCrtKey.getModulus(),
                            rsaPrivCrtKey.getPublicExponent(), rsaPrivCrtKey.getPrivateExponent(),
                            rsaPrivCrtKey.getPrimeP(), rsaPrivCrtKey.getPrimeQ(),
                            rsaPrivCrtKey.getPrimeExponentP(), rsaPrivCrtKey.getPrimeExponentQ(),
                            rsaPrivCrtKey.getCrtCoefficient(), rsaPrivCrtKey.getParams()));

                } else if (pkcs8KeySpec.isAssignableFrom(keySpec)) {
                    return keySpec.cast(new PKCS8EncodedKeySpec(key.getEncoded()));
                } else if (rsaPrivKeySpec.isAssignableFrom(keySpec)) {
                    java.security.interfaces.RSAPrivateKey rsaPrivKey = (java.security.interfaces.RSAPrivateKey) key;
                    return keySpec.cast(new RSAPrivateKeySpec(rsaPrivKey.getModulus(),
                            rsaPrivKey.getPrivateExponent(), rsaPrivKey.getParams()));
                } else {
                    throw new InvalidKeySpecException("Inappropriate key specification");
                }
            } else if (key instanceof java.security.interfaces.RSAPrivateKey) {
                // Determine valid key specs
                Class<?> rsaPrivKeySpec = Class.forName("java.security.spec.RSAPrivateKeySpec");
                Class<?> pkcs8KeySpec = Class.forName("java.security.spec.PKCS8EncodedKeySpec");
                if (rsaPrivKeySpec.isAssignableFrom(keySpec)) {
                    java.security.interfaces.RSAPrivateKey rsaPrivKey = (java.security.interfaces.RSAPrivateKey) key;
                    return keySpec.cast(new RSAPrivateKeySpec(rsaPrivKey.getModulus(),
                            rsaPrivKey.getPrivateExponent(), rsaPrivKey.getParams()));
                } else if (pkcs8KeySpec.isAssignableFrom(keySpec)) {
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
        checkKeyAlgo(key, type.keyAlgo());

        try {
            if (key instanceof java.security.interfaces.RSAPublicKey) {
                // Check if key originates from this factory
                if (key instanceof com.ibm.crypto.plus.provider.RSAPublicKey) {
                    return key;
                }
                // Convert key to spec
                RSAPublicKeySpec rsaPubKeySpec = (RSAPublicKeySpec) engineGetKeySpec(key,
                        RSAPublicKeySpec.class);
                // Create key from spec, and return it
                return engineGeneratePublic(rsaPubKeySpec);
            } else if (key instanceof java.security.interfaces.RSAPrivateCrtKey) {
                // Check if key originates from this factory
                if (key instanceof com.ibm.crypto.plus.provider.RSAPrivateCrtKey) {
                    return key;
                }
                // Convert key to spec
                RSAPrivateKeySpec rsaPrivKeySpec = (RSAPrivateKeySpec) engineGetKeySpec(key,
                        RSAPrivateCrtKeySpec.class);
                // Create key from spec, and return it
                return engineGeneratePrivate(rsaPrivKeySpec);
            } else if (key instanceof java.security.interfaces.RSAPrivateKey) {
                // Check if key originates from this factory
                if (key instanceof com.ibm.crypto.plus.provider.RSAPrivateKey) {
                    return key;
                }
                // Convert key to spec
                RSAPrivateKeySpec rsaPrivKeySpec = (RSAPrivateKeySpec) engineGetKeySpec(key,
                        RSAPrivateKeySpec.class);
                // Create key from spec, and return it
                return engineGeneratePrivate(rsaPrivKeySpec);
            } else {
                throw new InvalidKeyException("Wrong algorithm type");
            }
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException("Cannot translate key: " + e.getMessage());
        }
    }

    // Internal utility method for checking key algorithm
    private static void checkKeyAlgo(Key key, String expectedAlg) throws InvalidKeyException {
        String keyAlg = key.getAlgorithm();
        if (keyAlg == null) {
            //Thread.dumpStack();
            throw new InvalidKeyException("Expected a " + expectedAlg + " key, but got " + keyAlg);
        } else if (key.getAlgorithm().equalsIgnoreCase("MLKEM")) {
            return;
        } else if (!key.getAlgorithm().equalsIgnoreCase(expectedAlg)) {
            throw new InvalidKeyException("Expected a " + expectedAlg + " key, but got " + keyAlg);
        }


    }

    public static final class Legacy extends RSAKeyFactory {
        public Legacy(OpenJCEPlusProvider provider) {
            super(provider, KeyType.RSA);
        }
    }

    public static final class PSS extends RSAKeyFactory {
        public PSS(OpenJCEPlusProvider provider) {
            super(provider, KeyType.PSS);
        }
    }
}
