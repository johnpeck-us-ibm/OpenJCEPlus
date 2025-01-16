/*
 * Copyright IBM Corp. 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.security.internal.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;

public class MLKEMPublicKeySpec implements KeySpec {

    private final byte[] rawkeyE;
    private final AlgorithmParameterSpec params;

    /**
     * Creates a new MLKEMPublicKeySpec.
     *
     * @param rawekyE the bytes of the MLKEM public key
     */
    public MLKEMPublicKeySpec(byte[] rawkeyE) {
        this(rawkeyE, null);
    }

    /**
     * Creates a new MLKEMPublicKeySpec with additional key parameters.
     *
     * @param rawkeyE the bytes od the MLKEM public key
     * @param params  the parameters associated with this key, may be null
     */
    public MLKEMPublicKeySpec(byte[] rawkeyE, AlgorithmParameterSpec params) {
        this.rawkeyE = rawkeyE;
        this.params = params;
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
    public AlgorithmParameterSpec getParams() {
        return this.params;
    }
}
