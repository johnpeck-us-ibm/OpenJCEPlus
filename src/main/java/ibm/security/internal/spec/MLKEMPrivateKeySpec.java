/*
 * Copyright IBM Corp. 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

 package ibm.security.internal.spec;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;

public class MLKEMPrivateKeySpec implements KeySpec {

    private final byte[] rawkeyD;
    private final byte[] rawkeyE;
    private final AlgorithmParameterSpec params;

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
     * @param params the MLKEM Parameters for this key
     */
    public MlKEMPrivateKeySpec(byte[] rawkeyD, AlgorithmParameters params) {
        this(rawkeyD, null, params);
    }

    /**
     * Creates a new MLKEMPrivateKeySpec with additional key parameters.
     *
     * @param rawkeyD the bytes of the MLKEM private key
     * @param rawkeyE the bytes od the MLKEM public key, may be null
     * @param params the parameters associated with this key, may be null
     */
    public MLEKMPrivateKeySpec(byte[] rawkeyD, byte[] rawkeyE, AlgorithmParameterSpec params) {
        this.rawkeyD = rawkeyD;
        this.rawkeyE = rawkeyE;
        this.params = params;
    }

    /**
     * Returns the raw bytes associated with the private key.
     *
     * @return the the raw key bytes for this private key
     */
    public BigInteger getPrivateKeyRawBytes() {
        return this.rawkeyD;
    }

    /**
     * Returns the public key raw bytes, may be null if not present.
     *
     * @return the public key raw bytes.
     */
    public BigInteger getPublicKeyRawBytes() {
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
