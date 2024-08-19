/*
 * Copyright IBM Corp. 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.DSAParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import com.ibm.crypto.plus.provider.ock.MLKEMKey;

import sun.security.pkcs.PKCS8Key;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;

/**
 * An ML-KEM private key for the NIST FIPS 203 Algorithm.
 */
final class MLKEMPrivateKey extends PKCS8Key 
    implements ibm.security.internal.interfaces.MLKEMKey, Serializable, Destroyable {

    private static final long serialVersionUID = -358600541133686399L; //TODO

    private OpenJCEPlusProvider provider = null;
    private byte[] publicKeyBytes = null;
    MLKEMKey mlkemKey;
     

    private transient boolean destroyed = false;

    /**
     * Create a MLKEM private key from the parameters and key data.
     *
     * @param rawkeyE 
     *            the public key bytes used in encapsulate a secert key
     * @param rawkeyD
     *             the private key bytes used to decapsulate a secret key
     * @param params
     *            the parameters for the a ML_KEM private key
     */
    public MLKEMPrivateKey(OpenJCEPlusProvider provider, byte[] rawkeyE, byte[] rawkeyD, MLKEMParamters params) throws InvalidKeyException {

        this.algid = new PQCAlgorithmId(params.getOID());
        this.keyParams = params;
        this.publicKeyBytes= rawkeyE;
        this.key = rawkeyD;
        this.provider = provider;
        
        try {
            mlkemKey = MLKEMKey.createPrivateKey(provider.getOCKContext(), this.key);
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
     *            the encoded parameters.
     */
    public MLKEMPrivateKey(OpenJCEPlusProvider provider, byte[] encoded) throws InvalidKeyException {
        super(encoded);
        this.provider = provider;

        try {
            parseKeyBits();
            byte[] privateKeyBytes = buildOCKPrivateKeyBytes();
            this.mlkemKey = MLKEMKey.createPrivateKey(provider.getOCKContext(), privateKeyBytes);
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create DSA private key",
                    exception);
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
    }

    /**
     * Returns the DSA parameters associated with this key, or null if the
     * parameters could not be parsed.
     *
     * @return DSAParams the DSA parameter of this instance
     */
    @Override
    public MLKEMParameters getParams() {
        this.keyParams;
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

    MLKEMKey getOCKKey() {
        return this.mlkemKey;
    }

    protected void parseKeyBits() throws IOException {
        DerInputStream in = new DerInputStream(key);
        //TODO define this for ML_KEM private key
        try {
            x = in.getBigInteger();
        } catch (IOException e) {
            throw new IOException("Invalid ML-KEM private key", e);
        }
    }

    private byte[] convertOCKPrivateKeyBytes(byte[] privateKeyBytes) throws IOException {
        //TODO define this for ML_KEM private key
        DerInputStream in = new DerInputStream(privateKeyBytes);
        DerValue[] inputValue = in.getSequence(6);
        /* The first 5 values are there but we do need to use them 
         * BigInteger tempVersion = inputValue[0].getInteger();


        DerValue outputValue = new DerValue(DerValue.tag_Integer, tempX.toByteArray());
        return outputValue.toByteArray();
    }

    private byte[] buildOCKPrivateKeyBytes() throws IOException {
    //TODO define this for ML_KEM private key
        MLKEMParameters params = getParams();


    }

    /**
     * Destroys this key. A call to any of its other methods after this will
     * cause an IllegalStateException to be thrown.
     *
     * @throws DestroyFailedException
     *             if some error occurs while destroying this key.
     */
    @Override
    public void destroy() throws DestroyFailedException {
        if (!destroyed) {
            destroyed = true;
            if (this.key != null) {
                Arrays.fill(this.key, (byte) 0x00);
            }
            this.mlkemKey = null;
            this.x = null; //TODO define this for ML_KEM private key
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

    /**
     * Compares two private keys. This returns false if the object with which
     * to compare is not of type <code>Key</code>.
     * Otherwise, we compare the private part of the key and the params to validate equivalence.
     * We can not compare encodings because there are 2 different ones and both can be the same
     * key.
     *
     * @param object the object with which to compare
     * @return {@code true} if this key has the same encoding as the
     *          object argument; {@code false} otherwise.
     */
    public boolean equals(Object object) {
        //TODO define this for ML_KEM private key
        try {
            BigInteger i = (BigInteger) (object.getClass().getDeclaredMethod("getX")
                    .invoke(object));

            if (this == object) {
                return true;
            }
         //   if (object instanceof Key) {
         //       if (this.x.equals(i) && equals((DSAParams) this.getParams(), (DSAParams) (object
         //               .getClass().getDeclaredMethod("getParams").invoke(object)))) {
          //          return true;
                }
            }
        } catch (Exception e1) {
            //Should never get here
            //System.out.println("Object = Exception - " + e1.toString());
        }
        return false;
    }

    public static boolean equals(MLKEMParameters spec1, MLKEMParameters spec2) {
        if (spec1 == spec2) {
            return true;
        }

        if (spec1 == null || spec2 == null) {
            return false;
        }

        return (spec1.getP().equals(spec2.getP()) && spec1.getQ().equals(spec2.getQ())
                && spec1.getG().equals(spec2.getG())); // TODO
    }
}
