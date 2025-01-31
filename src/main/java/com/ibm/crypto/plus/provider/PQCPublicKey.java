/*
 * Copyright IBM Corp. 2024, 2025
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.OCKPQCKey;
import java.security.InvalidKeyException;
import java.util.Arrays;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import sun.security.util.BitArray;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X509Key;

@SuppressWarnings("restriction")
final class PQCPublicKey extends X509Key
        implements Destroyable {



    private static final long serialVersionUID = -29954L; // TODO

    private OpenJCEPlusProvider provider = null;
    private byte[] rawKey = null;
    private String name;

    private transient boolean destroyed = false;
    private transient OCKPQCKey pqcKey = null; // Transient per tag [SERIALIZATION] in DesignNotes.txt

    public PQCPublicKey(OpenJCEPlusProvider provider, byte[] rawKey, String algName)
            throws InvalidKeyException {
        this.algid = new AlgorithmId(PQCAlgorithmId.getOID(algName));
        this.provider = provider;
        this.rawKey = rawKey;
        this.name = algName;

        setKey(new BitArray(this.rawKey.length * 8, this.rawKey));

        try {
            this.pqcKey = OCKPQCKey.createPublicKey(provider.getOCKContext(), getEncoded());
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create RSA public key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
    }

    public PQCPublicKey(OpenJCEPlusProvider provider, OCKPQCKey pqcKey) {
        try {
            this.provider = provider;
            this.rawKey = pqcKey.getPublicKeyBytes();
            setKey(new BitArray(this.rawKey.length * 8, this.rawKey));
            this.pqcKey = pqcKey;
        } catch (Exception exception) {
            throw provider.providerException("Failure in DHPublicKey", exception);
        }
    }

    public PQCPublicKey(OpenJCEPlusProvider provider, byte[] encoded) throws InvalidKeyException {
        this.provider = provider;

        try {
            decode(encoded);

            this.pqcKey = OCKPQCKey.createPublicKey(provider.getOCKContext(),
                    /* publicKeyBytes */ this.rawKey);
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
        return name;
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

    OCKPQCKey getOCKKey() {
        return this.pqcKey;
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
            if (this.rawKey != null) {
                Arrays.fill(this.rawKey, (byte) 0x00);
            }
            this.rawKey = null;
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
                + (this.rawKey).toString() + "\n");

        return strbuf.toString();
    }

}
