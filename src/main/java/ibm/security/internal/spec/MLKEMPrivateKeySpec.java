/*
 * Copyright IBM Corp. 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.security.internal.spec;

import java.security.AlgorithmParameters;
import java.security.spec.KeySpec;

public class MLKEMPrivateKeySpec implements KeySpec {

    private final byte[] rawkeyD;
    private final byte[] rawkeyE;
    private final AlgorithmParameters params;

    /**
     * Creates a new MLKEMPrivateKeySpec.
     *
     * @param rawekyD the bytes of the MLKEM private key
     */
    public MLKEMPrivateKeySpec(byte[] rawkeyD) {
        this(rawkeyD, null, null);
    }

    /**
     * Creates a new MLKEMPrivateKeySpec.
     *
     * @param rawkeyD the bytes of the MLKEM private key
     * @param params  the MLKEM Parameters for this key
     */
    public MLKEMPrivateKeySpec(byte[] rawkeyD, AlgorithmParameters params) {
        this(rawkeyD, (byte[]) null, params);
    }

    /**
     * Creates a new MLKEMPrivateKeySpec with additional key parameters.
     *
     * @param rawkeyD the bytes of the MLKEM private key
     * @param rawkeyE the bytes od the MLKEM public key, may be null
     * @param params  the parameters associated with this key, may be null
     */
    public MLKEMPrivateKeySpec(byte[] rawkeyD, byte[] rawkeyE, AlgorithmParameters params) {
        this.rawkeyD = rawkeyD;
        this.rawkeyE = rawkeyE;
        this.params = params;
    }

    /**
     * Returns the raw bytes associated with the private key.
     *
     * @return the the raw key bytes for this private key
     */
    public byte[] getPrivateKeyRawBytes() {
        return this.rawkeyD;
    }

    /**
     * Returns the public key raw bytes, may be null if not present.
     *
     * @return the public key raw bytes.
     */
    public byte[] getPublicKeyRawBytes() {
        return this.rawkeyE;
    }

    /**
     * Returns the parameters associated with this key, may be null if not
     * present.
     *
     * @return the parameters associated with this key
     */
    public AlgorithmParameters getParams() {
        return this.params;
    }
}
