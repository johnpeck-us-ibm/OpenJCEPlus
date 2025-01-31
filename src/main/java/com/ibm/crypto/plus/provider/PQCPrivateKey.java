/*
 * Copyright IBM Corp. 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.OCKPQCKey;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import javax.security.auth.DestroyFailedException;
import sun.security.pkcs.PKCS8Key;
import sun.security.util.DerInputStream;
import sun.security.util.DerValue;
import sun.security.x509.AlgorithmId;

/*
 * A PQC private key for the NIST FIPS 203 Algorithm.
 */
@SuppressWarnings("restriction")
final class PQCPrivateKey extends PKCS8Key {

    private static final long serialVersionUID = 4356472124L; // TODO

    private OpenJCEPlusProvider provider = null;
    private final byte[] rawKey;
    private final String name;

    OCKPQCKey pqcKey;

    private transient boolean destroyed = false;

    /**
     * Create a MLKEM private key from the parameters and key data.
     *
     * @param keyBytes
     *                the private key bytes used to decapsulate a secret key
     */
    public PQCPrivateKey(OpenJCEPlusProvider provider, byte[] keyBytes, String algName)
            throws InvalidKeyException {

        this.algid = new AlgorithmId(PQCAlgorithmId.getOID(algName));
        this.rawKey = keyBytes;
        this.name = algName;
        this.provider = provider;

        DerValue val = new DerValue(DerValue.tag_OctetString, keyBytes);

        try {
            this.key = val.toByteArray();
        } finally {
            val.clear();
        }

        try {
            // Currently the ICC expects the raw keys.
            pqcKey = OCKPQCKey.createPrivateKey(provider.getOCKContext(), algName, this.key);
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
    public PQCPrivateKey(OpenJCEPlusProvider provider, OCKPQCKey ockKey) throws InvalidKeyException {
        try {
            this.provider = provider;
            this.pqcKey = ockKey;
            this.rawKey = ockKey.getPrivateKeyBytes();
            this.name = ockKey.getAlgorithm();

            // This needs to be checked. We want to use PKCS8 keys with OCKC. Check if we need to do this.
            DerValue val = new DerValue(DerValue.tag_OctetString, this.rawKey);

            try {
                this.key = val.toByteArray();
            } finally {
                val.clear();
            }
        } catch (Exception exception) {
            throw provider.providerException("Failure in PQCPrivateKey", exception);
        }
    }

    /**
     * Create a private key from it's DER encoding (PKCS#8)
     *
     * @param encoded
     *                the encoded parameters.
     */
    public PQCPrivateKey(OpenJCEPlusProvider provider, byte[] encoded) throws InvalidKeyException {
        super(encoded);
        this.provider = provider;

        try {
            rawKey = new DerInputStream(key).getOctetString();
        } catch (IOException e) {
            throw new InvalidKeyException("Cannot parse input", e);
        }
        
        this.name = this.algid.getName();

        try {
            // Currently the ICC expects the raw keys.
            this.pqcKey = OCKPQCKey.createPrivateKey(provider.getOCKContext(), this.algid.getName(), this.key);
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create PQC private key",
                    exception);
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
    }

    @Override
    public String getAlgorithm() {
        checkDestroyed();
        return name;
    }

    @Override
    public byte[] getEncoded() {
        checkDestroyed();
        return super.getEncoded();
    }

    OCKPQCKey getOCKKey() {
        return this.pqcKey;
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
                Arrays.fill(this.rawKey, (byte) 0x00);
            }
            this.pqcKey = null;
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

}
