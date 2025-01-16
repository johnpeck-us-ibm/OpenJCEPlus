/*
 * Copyright IBM Corp. 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.security.internal.spec;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;

public class MLKEMParameterSpec implements AlgorithmParameterSpec {

    // Key Parameters.
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

    /**
     * Constructs a CCMParameterSpec object using the specified
     * authentication tag bit-length and the specified initialization vector.
     *
     * @param k the K parameter for ML-KEM key pairs. All other parameters based off
     *          the k value.
     *
     * @throws IllegalArgumentException if {@code tLen} is not an integer multiple
     *                                  of 16
     *                                  between 32 and 128 inclusive, or if
     *                                  {@code iv} is null,
     *                                  or if the byte length of {@code iv} is not
     *                                  between 7 to 13 inclusive.
     */
    public MLKEMParameterSpec(BigInteger k) {
        if ((k.intValue() < 2) && (k.intValue() > 4)) {
            throw new IllegalArgumentException("k was be 2, 3, or 4");
        }

        init(k);
    }

    /*
     * Check input parameters.
     */
    private void init(BigInteger k) {

        if ((k.intValue() < 2) || (k.intValue() > 4)) {
            throw new IllegalArgumentException(
                    "k key parameter must be 2, 3 or 4.");
        }
        this.k = k;

        setParameters(this.k);

    }

    /**
     * Returns the relative key strength.
     *
     * @return the authentication tag length (in bits)
     */
    public int getKeySize() {
        int size = 512;
        if (k.equals(new BigInteger("3"))) {
            size = 786;
        } else if (k.equals(new BigInteger("4"))) {
            size = 1024;
        }
        return size;
    }

    /**
     * Returns the value of the K parameter.
     *
     * @return K parameter
     */
    public BigInteger getK() {

        return this.k;
    }

    /**
     * Returns the value of the N parameter.
     *
     * @return the N parameter.
     */
    public BigInteger getN() {

        return this.n;
    }

    /**
     * Returns The Q Parameter.
     *
     * @return the value of the Q parameter.
     */
    public BigInteger getQ() {

        return this.q;
    }

    /**
     * Returns the N1 Parameter.
     *
     * @return the value of the N1 parameter
     */
    public BigInteger getN1() {

        return this.n1;
    }

    /**
     * Returns the value of the N2 parameter.
     *
     * @return N2 parameter
     */
    public BigInteger getN2() {

        return this.n2;
    }

    /**
     * Returns the DU parameter
     *
     * @return the DU parameter
     */
    public BigInteger getDU() {

        return this.du;
    }

    /**
     * Returns the DV parameter.
     *
     * @return the DV Parameter
     */
    public BigInteger getDV() {

        return this.dv;
    }

    /**
     * Returns the private key byte length.
     *
     * @return private key length in bytes
     */
    public int getPrivateKeyLen() {

        return this.privKeyLen;
    }

    /**
     * Returns the public key byte length.
     *
     * @return public key length in bytes
     */
    public int getPublcKeyLen() {

        return this.publicKeyLen;
    }

    /**
     * Returns the cipher text byte length.
     *
     * @return cipher text length in bytes
     */
    public int getCipherTextLen() {

        return this.cipherTextLen;
    }

    /**
     * Returns the strength of the shared Secret key in bits.
     *
     * @return Strength of shared Secret key in bits.
     */
    public int getSecretKeySize() {

        return 256;
    }

    /**
     * FIll in all the other parameters
     * 
     * @param k
     * 
     */
    private void setParameters(BigInteger k) {
        this.n = new BigInteger("256");
        this.q = new BigInteger("3329");
        this.k = k;

        switch (k.intValue()) {
            case 2:
                this.n1 = new BigInteger("3");
                this.n2 = new BigInteger("2");
                this.du = new BigInteger("10");
                this.dv = new BigInteger("4");
                this.privKeyLen = 800;
                this.publicKeyLen = 1632;
                this.cipherTextLen = 768;
                break;
            case 3:
                this.n1 = new BigInteger("2");
                this.n2 = new BigInteger("2");
                this.du = new BigInteger("10");
                this.dv = new BigInteger("4");
                this.privKeyLen = 1184;
                this.publicKeyLen = 2400;
                this.cipherTextLen = 1088;
                break;
            case 4:
                this.n1 = new BigInteger("2");
                this.n2 = new BigInteger("2");
                this.du = new BigInteger("11");
                this.dv = new BigInteger("5");
                this.privKeyLen = 1568;
                this.publicKeyLen = 3168;
                this.cipherTextLen = 1568;
                break;
        }
    }

}
