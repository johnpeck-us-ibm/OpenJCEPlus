/*
 * Copyright IBM Corp. 2024, 2025
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
import javax.security.auth.Destroyable;
import sun.security.util.BitArray;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X509Key;

@SuppressWarnings("restriction")
final class MLKEMPublicKey extends X509Key
        implements Destroyable {

    /**
     * 
     */

    private static final long serialVersionUID = -2993913181811776154L; // TODO

    private OpenJCEPlusProvider provider = null;
    private byte[] key = null;
    private byte[] encodedKey = null;

    private transient boolean destroyed = false;
    private transient OCKMLKEMKey mlkemKey = null; // Transient per tag [SERIALIZATION] in DesignNotes.txt

    public MLKEMPublicKey(AlgorithmId algId, OpenJCEPlusProvider provider, byte[] rawKeyE)
            throws InvalidKeyException {
        this.algid = algId;
        this.provider = provider;
        this.key = rawKeyE;
        setKey(new BitArray(this.key.length * 8, this.key));

        try {
            this.mlkemKey = OCKMLKEMKey.createPublicKey(provider.getOCKContext(), this.key);
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create RSA public key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
    }

    public MLKEMPublicKey(OpenJCEPlusProvider provider, OCKMLKEMKey mlkemKey) {
        try {
            this.provider = provider;
            this.key = mlkemKey.getPublicKeyBytes();
            this.mlkemKey = mlkemKey;
        } catch (Exception exception) {
            throw provider.providerException("Failure in DHPublicKey", exception);
        }
    }

    public MLKEMPublicKey(OpenJCEPlusProvider provider, byte[] encoded) throws InvalidKeyException {
        this.provider = provider;

        try {
            decode(encoded);

            this.mlkemKey = OCKMLKEMKey.createPublicKey(provider.getOCKContext(),
                    /* publicKeyBytes */ this.key);
        } catch (Exception e) {
            throw provider.providerException("Failure in MLKEMPublicKey", e);
        }
    }

    /**
     * Returns the name of the algorithm associated with this key: "ML-KEM"
     */
    @Override
    public String getAlgorithm() {
        checkDestroyed();
        String algName = null;
        int size = this.key.length;
        switch (size) {
            case 1632:
                algName = "ML_KEM_512";
                break;
            case 2400:
                algName = "ML_KEM_768";
                break;
            case 3168:
                algName = "ML_KEM_1024";
        }
        return algName;
    }

    /**
     * Returns the encoding format of this key: "X.509"
     */
    @Override
    public String getFormat() {
        checkDestroyed();
        return super.getFormat();
    }

    @Override
    public byte[] getEncoded() {
        checkDestroyed();

        return (byte[]) this.encodedKey.clone();
    }

    OCKMLKEMKey getOCKKey() {
        return this.mlkemKey;
    }

    /**
     * Destroys this key. A call to any of its other methods after this will cause
     * an IllegalStateException to be thrown.
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
            this.key = null;
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

    public String toString() {
        // public String toString() {
        StringBuffer strbuf = new StringBuffer("OpenJCEPlus ML-KEM Public Key:\n" + "k:\n"
                + (this.key).toString() + "\n");

        return strbuf.toString();
    }

}
