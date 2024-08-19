/*
 * Copyright IBM Corp. 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyRep;
import java.security.PublicKey;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import com.ibm.crypto.plus.provider.ock.MLKEMKey;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.X509Key;

@SuppressWarnings("restriction")
final class MLKEMPublicKey extends X509Key
        implements javax.crypto.interfaces.MLKEMPublicKey, PublicKey, Serializable, Destroyable {

    /**
     * 
     */

    private static final long serialVersionUID = -2993913181811776154L; //TODO

    private OpenJCEPlusProvider provider = null;
    private MLKEMParameters mlkemParams = null;
    private byte[] key = null;
    private byte[] encodedKey = null;
   


    private transient boolean destroyed = false;
    private transient MLKEMKey  mlkemKey= null; // Transient per tag [SERIALIZATION] in DesignNotes.txt

    public MLKEMPublicKey(OpenJCEPlusProvider provider, byte rawKeyD, BigInteger k)
            throws InvalidKeyException {
        this(provider, rawKeyD, k);
    }

    /**
     * Make a DH public key out of a public value <code>y</code>, a prime modulus
     * <code>p</code>, a base generator <code>g</code>, and a private-value length
     * <code>l</code>.
     *

     *
     * @exception InvalidKeyException
     *                if the key cannot be encoded
     */
    public MLKEMPublicKey(OpenJCEPlusProvider provider, byte[] rawKeyD , MLKEMParameters params)
            throws InvalidKeyException {
        this.provider = provider;
        this.mlkemParams = params;
        this.key = rawKeyD;
        this.k = mlkemParams.getK();
        this.encodedKey = getEncoded();
    }

    public MLEKMPublicKey(OpenJCEPlusProvider provider, MLKEMKey mlkemKey) {
        try {
            this.provider = provider;
            convertOCKPublicKeyBytes(mlkemKey.getPublicKeyBytes());
            this.mlkemKey = mlkemKey;
            parseKeyBits();
        } catch (Exception exception) {
            throw provider.providerException("Failure in DHPublicKey", exception);
        }
    }

    public MLKEMPublicKey(OpenJCEPlusProvider provider, byte[] encoded) throws InvalidKeyException {
        this.provider = provider;

        // decode(encoded);

        try {

            // System.out.println ("In DHPublicKey(Provider, byte[] encoded" +
            // ECUtils.bytesToHex(encoded));
            convertOCKPublicKeyBytes(encoded);

            buildOCKPublicKeyBytes();
            // System.out.println ("In DHPublicKey(Provider, byte[] encoded publicKeyBytes"
            // + ECUtils.bytesToHex(publicKeyBytes));

            this.mlkemKey = mlkemKey.createPublicKey(provider.getOCKContext(),
                    /* publicKeyBytes */ this.encodedKey);

            // System.err.println("Afte OCK: " + ECUtils.bytesToHex(this.key));

        } catch (IOException ioex) {
            throw new InvalidKeyException("Invalid key format");
        } catch (Exception e) {
            throw provider.providerException("Failure in MLKEMPublicKey", e);
        }
    }

    private byte[] convertOCKPublicKeyBytes(byte[] encodedKey) throws IOException {
        /* TODO not sure what the encodings are to look like
        /*
         * DerInputStream in = new DerInputStream(publicKeyBytes); DerValue[] inputValue
         * = in.getSequence(3); BigInteger tempY = inputValue[0].getInteger();
         * BigInteger tempP = inputValue[1].getInteger(); BigInteger tempG =
         * inputValue[2].getInteger();
         * 
         * DerValue outputValue = new DerValue(DerValue.tag_Integer,
         * tempY.toByteArray()); return outputValue.toByteArray();
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
            if (derInStream.available() == 0) {
                throw new IOException("Parameters missing");
            }

            /*
             * Parse the parameters
             */
            DerValue params = derInStream.getDerValue();
            if (params.getTag() == DerValue.tag_Null) {
                throw new IOException("Null parameters");
            }
            if (params.getTag() != DerValue.tag_Sequence) {
                throw new IOException("Parameters not a SEQUENCE");
            }
            params.getData().reset();
            BigInteger p = params.getData().getDerValue().getBigInteger();
            BigInteger g = params.getData().getDerValue().getBigInteger();
            int l = -1;
            // Private-value length is OPTIONAL
            if (params.getData().available() != 0) {
                l = params.getData().getInteger();
            }
            if (params.getData().available() != 0) {
                throw new IOException("Extra parameter data");
            }


            /*
             * Parse the key
             */

            this.key = derKeyVal.getData().getBitString();

            //customParseKeyBits();
            parseKeyBits();
            if (derKeyVal.getData().available() != 0) {
                throw new InvalidKeyException("Excess key data");
            }

            dhParams = new DHParameters(provider);
            dhParams.engineInit((l == -1) ? new DHParameterSpec(p, g, y.bitLength())
                    : new DHParameterSpec(p, g, l));

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

    private byte[] buildOCKPublicKeyBytes() throws Exception {
        // TODO

        DerValue[] value = new DerValue[3];

        value[0] = new DerValue(DerValue.tag_Integer, this.y.toByteArray());
        value[1] = new DerValue(DerValue.tag_Integer, dhParams.getP().toByteArray());
        value[2] = new DerValue(DerValue.tag_Integer, dhParams.getG().toByteArray());

        DerOutputStream asn1Key = new DerOutputStream();
        try {
            asn1Key.putSequence(value);
        } finally {
            closeStream(asn1Key);
        }

        return asn1Key.toByteArray();
    }

    protected void parseKeyBits() throws InvalidKeyException {
        //TODO
        try {

            DerInputStream in = new DerInputStream(this.key);
            this.y = in.getBigInteger();

        } catch (IOException e) {
            throw new InvalidKeyException(e.toString());
        }

    }

    /**
     * Returns the key parameters.
     *
     * @return the key parameters
     */
    @Override
    public MLKEMParameterSpec getParams() {
        checkDestroyed();
        try {
            return this.mlkemParams.engineGetParameterSpec(MLKEMParameterSpec.class);
        } catch (InvalidParameterSpecException e) {
            throw provider.providerException("Failure in DHPublicKey", e);
        }
    }

    /**
     * Returns the name of the algorithm associated with this key: "DH"
     */
    @Override
    public String getAlgorithm() {
        checkDestroyed();
        return "MLKEM";
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
        //TODO
        /**
         * Get the encoding of the key.
         */
        DerOutputStream params = null;
        DerOutputStream algid = null;
        DerOutputStream tmpDerKey = null;
        DerOutputStream derKey = null;
        if (this.encodedKey == null) {
            try {
                algid = new DerOutputStream();

                // store oid in algid
                algid.putOID(ObjectIdentifier.of(DH_data));

                // encode parameters
                params = new DerOutputStream();
                params.putInteger(this.dhParams.getP());
                params.putInteger(this.dhParams.getG());
                if (this.dhParams.getL() != 0) {
                    params.putInteger(BigInteger.valueOf(this.dhParams.getL()));
                }
                // wrap parameters into SEQUENCE
                DerValue paramSequence = new DerValue(DerValue.tag_Sequence, params.toByteArray());
                // store parameter SEQUENCE in algid
                algid.putDerValue(paramSequence);

                // wrap algid into SEQUENCE, and store it in key encoding
                tmpDerKey = new DerOutputStream();
                tmpDerKey.write(DerValue.tag_Sequence, algid);

                // store key data
                tmpDerKey.putBitString(this.key);

                // wrap algid and key into SEQUENCE
                derKey = new DerOutputStream();
                derKey.write(DerValue.tag_Sequence, tmpDerKey);
                this.encodedKey = derKey.toByteArray();
            } catch (IOException e) {
                return null;
            } finally {
                closeStream(params);
                closeStream(algid);
                closeStream(tmpDerKey);
                closeStream(derKey);

            }
        }
        return (byte[]) this.encodedKey.clone();
    }

    /**
     * Returns the public value, <code>y</code>.
     *
     * @return the public value, <code>y</code>
     */
    @Override
    public BigInteger getK() {
        checkDestroyed();
        return this.mlkemParams.getK();
    }

    DHKey getOCKKey() {
        return this.key; //? TODO
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
