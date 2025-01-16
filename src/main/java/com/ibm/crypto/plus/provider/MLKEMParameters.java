/*
 * Copyright IBM Corp. 2024, 2025
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import ibm.security.internal.spec.MLKEMParameterSpec;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;

public final class MLKEMParameters extends AlgorithmParametersSpi {

    protected BigInteger n;
    protected BigInteger q;
    protected BigInteger k;
    protected BigInteger n1;
    protected BigInteger n2;
    protected BigInteger du;
    protected BigInteger dv;
    protected int privKeyLen;
    protected int publicKeyLen;
    protected int cipherTextLen;

    public MLKEMParameters() {

    }

    /**
     * Initialize the MLKEMParameters by a MLKEMParameterSpec
     *
     * @param paramSpec
     *                  the ML-KEM algorithm parameter spec for this instance.
     */
    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException {
        if (!(paramSpec instanceof MLKEMParameterSpec)) {
            throw new InvalidParameterSpecException("Inappropriate parameter specification");
        }
        this.n = ((MLKEMParameterSpec) paramSpec).getN();
        this.q = ((MLKEMParameterSpec) paramSpec).getQ();
        this.k = ((MLKEMParameterSpec) paramSpec).getK();
        this.n1 = ((MLKEMParameterSpec) paramSpec).getN1();
        this.n2 = ((MLKEMParameterSpec) paramSpec).getN2();
        this.du = ((MLKEMParameterSpec) paramSpec).getDU();
        this.dv = ((MLKEMParameterSpec) paramSpec).getDV();
        this.privKeyLen = ((MLKEMParameterSpec) paramSpec).getPrivateKeyLen();
        this.publicKeyLen = ((MLKEMParameterSpec) paramSpec).getPublcKeyLen();
        this.cipherTextLen = ((MLKEMParameterSpec) paramSpec).getCipherTextLen();
    }

    /**
     * Initialize the MLKEMParameters by encoded bytes
     *
     * @param params
     *               the encoded bytes of the parameters.
     */
    @Override
    protected void engineInit(byte[] params) throws IOException {
        DerValue encoded = new DerValue(params);

        if (encoded.getTag() != DerValue.tag_Sequence) {
            throw new IOException("DSA params parsing error");
        }

        encoded.getData().reset();

        if (encoded.getData().available() != 0) {
            throw new IOException(
                    "encoded params have " + encoded.getData().available() + " extra bytes");
        }
    }

    /**
     * Initialize the MLKEMParameters by encoded bytes with the specified decoding
     * method.
     *
     * @param params
     *                       the encoded bytes of the parameters.
     * @param decodingMethod
     *                       the decoding method to be used.
     */
    @Override
    protected void engineInit(byte[] params, String format) throws IOException {
        engineInit(params);
    }

    /**
     * Return the parameter spec used by this parameter instance.
     *
     * @param paramSpec
     *                  the parameter spec class to be returned
     *
     * @return AlgorithmParameterSpec the newly generated parameterSpec
     */
    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec)
            throws InvalidParameterSpecException {
        try {
            Class<?> MLKEMParamSpec = Class.forName("ibm.security.internal.spec.MLKEMParameterSpec");
            if (MLKEMParamSpec.isAssignableFrom(paramSpec)) {
                return paramSpec.cast(new MLKEMParameterSpec(this.k));
            } else {
                throw new InvalidParameterSpecException("Inappropriate parameter Specification");
            }
        } catch (ClassNotFoundException e) {
            throw new InvalidParameterSpecException(
                    "Unsupported parameter specification: " + e.getMessage());
        }
    }

    /**
     * Returns the parameters in encoded bytes.
     *
     * @return byte[] the encoded parameters
     */
    @Override
    protected byte[] engineGetEncoded() throws IOException {
        DerOutputStream out = null;
        DerOutputStream bytes = null;
        try {
            out = new DerOutputStream();
            bytes = new DerOutputStream();
            bytes.putInteger(this.n);
            bytes.putInteger(this.q);
            bytes.putInteger(this.k);
            bytes.putInteger(this.n1);
            bytes.putInteger(this.n2);
            bytes.putInteger(this.du);
            bytes.putInteger(this.dv);
            bytes.putInteger(this.privKeyLen);
            bytes.putInteger(this.publicKeyLen);
            bytes.putInteger(this.cipherTextLen);
            out.write(DerValue.tag_Sequence, bytes);
            return out.toByteArray();
        } finally {
            out.close();
            bytes.close();
        }
    }

    /**
     * Returns the parameters in encoded bytes with encoding method specified.
     *
     * @return byte[] encoded parameters.
     */
    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
        return engineGetEncoded();
    }

    /*
     * Returns a formatted string describing the parameters.
     */
    @Override
    protected String engineToString() {
        return "\n\tk: " + k.toString() + "\n";
    }

}
