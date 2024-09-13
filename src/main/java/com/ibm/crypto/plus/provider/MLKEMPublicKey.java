/*
 * Copyright IBM Corp. 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.OCKMLKEMKey;
import ibm.security.internal.spec.MLKEMParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyRep;
import java.security.PublicKey;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import javax.security.auth.Destroyable;
import javax.security.auth.DestroyFailedException;
import sun.security.util.BitArray;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X509Key;


@SuppressWarnings("restriction")
final class MLKEMPublicKey extends X509Key
        implements PublicKey, Serializable, Destroyable {

    /**
     * 
     */

    private static final long serialVersionUID = -2993913181811776154L; //TODO

    private OpenJCEPlusProvider provider = null;
    private MLKEMParameters mlkemParams = null;
    private byte[] key = null;
    private byte[] encodedKey = null;

    private transient boolean destroyed = false;
    private transient OCKMLKEMKey  mlkemKey= null; // Transient per tag [SERIALIZATION] in DesignNotes.txt

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

    /**
     * Parameters not used with ML-KEM. So, this is not really needed but is here just in case.
     *
     * @exception InvalidKeyException
     *                if the key cannot be encoded
     */
    public MLKEMPublicKey(AlgorithmId algId, OpenJCEPlusProvider provider, byte[] rawKeyE , MLKEMParameters params)
            throws InvalidKeyException {
        this(algId, provider, rawKeyE);
        this.mlkemParams = params;
    }

    public MLEKMPublicKey(AlgorithmId algId, OpenJCEPlusProvider provider, OCKMLKEMKey mlkemKey) {
        try {
            this.provider = provider;
            this.key = mlkemKey.getPublicKeyBytes());
            this.mlkemKey = mlkemKey;
        } catch (Exception exception) {
            throw provider.providerException("Failure in DHPublicKey", exception);
        }
    }

    public MLKEMPublicKey(OpenJCEPlusProvider provider, byte[] encoded) throws InvalidKeyException {
        this.provider = provider;

        try {
            decode(encoded);

            this.mlkemKey = mlkemKey.createPublicKey(provider.getOCKContext(),
                    /* publicKeyBytes */ this.key);

        } catch (IOException ioex) {
            throw new InvalidKeyException("Invalid key format");
        } catch (Exception e) {
            throw provider.providerException("Failure in MLKEMPublicKey", e);
        }
    }

    private byte[] decode(byte[] encodedKey) throws IOException {
        /* SubjectPublicKeyInfo {PUBLIC-KEY: IOSet} ::= SEQUENCE {
         *        algorithm        AlgorithmIdentifier {PUBLIC-KEY, {IOSet}},
         *       subjectPublicKey BIT STRING
         * }
         */ 

        InputStream inStream = new ByteArrayInputStream(encodedKey);
        try {
            DerValue derKeyVal = new DerValue(inStream);
            if (derKeyVal.getTag() != DerValue.tag_Sequence) {
                throw new IOException("Invalid key format");
            }

            /*
             * Parse the algorithm identifier
             */
            DerValue algid = derKeyVal.getData().getDerValue();
            if (algid.getTag() != DerValue.tag_Sequence) {
                throw new IOException("AlgId is not a SEQUENCE");
            }
            DerInputStream derInStream = algid.toDerInputStream();
            derInStream.getOID();
            //FIPS 202 indicates that there are no parameters with Alg ID
            if (derInStream.available() != 0) {
                throw new IOException("Parameters available. Not to standard.");
            }

            /*
             * Parse the key
             */

            this.key = derKeyVal.getData().getBitString();

            this.encodedKey = (byte[]) encodedKey.clone();

            DerValue outputValue = new DerValue(DerValue.tag_Integer, this.key);

            return outputValue.toByteArray();

        } catch (IOException | NumberFormatException e) {
            throw new IOException("Error parsing key encoding", e);
        } catch (InvalidKeyException e) {
            throw new IOException("Error parsing key material", e);
        } catch (InvalidParameterSpecException e) {
            throw new IOException("Error creating DHParameters", e);
        }
    }

    /**
     * Parameters not used with ML-KEM keys
     *
     * @return null always.
     */
    @Override
    public MLKEMParameterSpec getParams() {
        checkDestroyed();
        return null;
    }

    /**
     * Returns the name of the algorithm associated with this key: "ML-KEM"
     */
    @Override
    public String getAlgorithm() {
        checkDestroyed();
        return "ML-KEM";
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
     *             if some error occurs while destroying this key.
     */
    @Override
    public void destroy() throws DestroyFailedException {
        if (!destroyed) {
            destroyed = true;
            if (this.key != null) {
                Arrays.fill(this.key, (byte) 0x00);
            }
            this.key = null;
            this.mlkemParams = null;
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
                + (this.k).toString() + "\n");

        return strbuf.toString();
    }



}
