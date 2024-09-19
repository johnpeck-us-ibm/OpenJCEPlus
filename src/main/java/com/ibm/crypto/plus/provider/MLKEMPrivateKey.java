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
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import com.ibm.crypto.plus.provider.ock.OCKMLKEMKey;

import ibm.security.internal.interfaces.MLKEMKey;
import sun.security.pkcs.PKCS8Key;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.x509.AlgorithmId;

/*
 * An ML-KEM private key for the NIST FIPS 203 Algorithm.
 */
@SuppressWarnings("restriction")
final class MLKEMPrivateKey extends PKCS8Key implements Serializable, Destroyable {

    private static final long serialVersionUID = -358600541133686399L; //TODO

    private OpenJCEPlusProvider provider = null;
    private byte[] keyE = null;
    OCKMLKEMKey mlkemKey;
     

    private transient boolean destroyed = false;

    /**
     * Create a MLKEM private key from the parameters and key data.
     *
     * @param rawkeyE 
     *            the public key bytes used in encapsulate a secert key can be null;
     * @param rawkeyD
     *             the private key bytes used to decapsulate a secret key
     */
    public MLKEMPrivateKey(AlgorithmId algId, OpenJCEPlusProvider provider, byte[] rawkeyE, byte[] rawkeyD) throws InvalidKeyException {

        this.algid = algid;
        this.keyE = rawkeyE;
        this.key = rawkeyD;
        this.provider = provider;
        
        try {
            //Currently the ICC expects the raw keys.
            mlkemKey = OCKMLKEMKey.createPrivateKey(provider.getOCKContext(), this.key);
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
            //Currently the ICC expects the raw keys.
            this.mlkemKey = OCKMLKEMKey.createPrivateKey(provider.getOCKContext(), this.key);
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create DSA private key",
                    exception);
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
    }

    /**
     * Parameters are not used with ML-KEM.
     *
     * @return parameters not required for ML-KEM
     */
    @Override
    public MLKEMParameters getParams() {
        return null;
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

}
