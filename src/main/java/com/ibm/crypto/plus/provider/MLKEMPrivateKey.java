/*
 * Copyright IBM Corp. 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.OCKMLKEMKey;
import java.security.InvalidKeyException;
import java.util.Arrays;
import javax.security.auth.DestroyFailedException;
import sun.security.pkcs.PKCS8Key;
import sun.security.x509.AlgorithmId;

/*
 * An ML-KEM private key for the NIST FIPS 203 Algorithm.
 */
@SuppressWarnings("restriction")
final class MLKEMPrivateKey extends PKCS8Key {

    private static final long serialVersionUID = -358600541133686399L; // TODO

    private OpenJCEPlusProvider provider = null;
    private byte[] keyE = null;
    OCKMLKEMKey mlkemKey;

    private transient boolean destroyed = false;

    /**
     * Create a MLKEM private key from the parameters and key data.
     *
     * @param rawkeyE
     *                the public key bytes used in encapsulate a secert key can be
     *                null;
     * @param rawkeyD
     *                the private key bytes used to decapsulate a secret key
     */
    public MLKEMPrivateKey(AlgorithmId algId, OpenJCEPlusProvider provider, byte[] rawkeyE, byte[] rawkeyD)
            throws InvalidKeyException {

        this.algid = algId;
        this.keyE = rawkeyE;
        this.key = rawkeyD;
        this.provider = provider;

        try {
            // Currently the ICC expects the raw keys.
            mlkemKey = OCKMLKEMKey.createPrivateKey(provider.getOCKContext(), algid.getName(), this.key);
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create ML-KEM private key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }

    }

    /**
     * Create a ML_KEM private key from it's DER encoding (PKCS#8)
     *
     * @param encoded
     *                the encoded parameters.
     */
    public MLKEMPrivateKey(OpenJCEPlusProvider provider, OCKMLKEMKey ockKey) throws InvalidKeyException {
        try {
            this.provider = provider;
            this.mlkemKey = ockKey;
            this.key = mlkemKey.getPrivateKeyBytes();
        } catch (Exception exception) {
            throw provider.providerException("Failure in MLKEMPrivateKey", exception);
        }
    }

    /**
     * Create a ML_KEM private key from it's DER encoding (PKCS#8)
     *
     * @param encoded
     *                the encoded parameters.
     */
    public MLKEMPrivateKey(OpenJCEPlusProvider provider, byte[] encoded) throws InvalidKeyException {
        super(encoded);
        this.provider = provider;

        try {
            // Currently the ICC expects the raw keys.
            this.mlkemKey = OCKMLKEMKey.createPrivateKey(provider.getOCKContext(), this.algid.getName(), this.key);
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create DSA private key",
                    exception);
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
    }

    @Override
    public String getAlgorithm() {
        checkDestroyed();
        return super.getAlgorithm();
    }

    @Override
    public byte[] getEncoded() {
        checkDestroyed();
        return super.getEncoded();
    }

    OCKMLKEMKey getOCKKey() {
        return this.mlkemKey;
    }

    /**
     * Destroys this key. A call to any of its other methods after this will
     * cause an IllegalStateException to be thrown.
     *
     * @throws DestroyFailedException
     *                                if some error occurs while destroying this
     *                                key.
     */
    @Override
    public void destroy() throws DestroyFailedException {
        if (!destroyed) {
            destroyed = true;
            if (this.key != null) {
                Arrays.fill(this.key, (byte) 0x00);
            }
            this.mlkemKey = null;
            this.keyE = null;
        }
    }

    /** Determines if this key has been destroyed. */
    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

    private void checkDestroyed() {
        if (destroyed) {
            throw new IllegalStateException("This key is no longer valid");
        }
    }

}
