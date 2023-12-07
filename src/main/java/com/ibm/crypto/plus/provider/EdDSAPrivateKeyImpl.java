/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyRep;
import java.security.interfaces.EdECPrivateKey;
import java.util.Arrays;
import java.util.Optional;
import com.ibm.crypto.plus.provider.ock.XECKey;
import ibm.security.internal.spec.NamedParameterSpec;
import sun.security.pkcs.PKCS8Key;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;

public final class EdDSAPrivateKeyImpl extends PKCS8Key implements EdECPrivateKey {

    private static final long serialVersionUID = 1L;

    private static final byte TAG_PARAMETERS_ATTRS = 0x00;
    private OpenJCEPlusProvider provider = null;
    private Optional<byte[]> h;
    private NamedParameterSpec paramSpec;
    private Exception exception = null; // In case an exception happened and the API did
    // not allow us to throw it, we throw it at the end

    private transient XECKey xecKey = null;

    private void setFieldsFromXeckey() throws Exception {
        if (this.key == null) {
            this.key = extractPrivateKeyFromOCK(xecKey.getPrivateKeyBytes()); // Extract key from GSKit and sets params
            this.h = Optional.of(key);
            this.algid = XECKey.getAlgId(this.paramSpec.getCurve());
        }
    }


    /**
     * Construct a key from an internal XECKey.
     *
     * @param provider
     * @param xecKey
     */
    public EdDSAPrivateKeyImpl(OpenJCEPlusProvider provider, XECKey xecKey)
            throws InvalidKeyException {
        if (provider == null)
            throw new InvalidKeyException("provider cannot be null");
        if (xecKey == null)
            throw new InvalidKeyException("xecKey cannot be null");
        this.xecKey = xecKey;
        this.provider = provider;
        try {
            setFieldsFromXeckey();
        } catch (Exception e) {
            throw new InvalidKeyException(e.getMessage());
        }
    }

    public EdDSAPrivateKeyImpl(OpenJCEPlusProvider provider,
            java.security.spec.NamedParameterSpec params, Optional<byte[]> h)
            throws InvalidKeyException {

        this.provider = provider;
        this.paramSpec = new NamedParameterSpec(params.getName());

        try {
            this.algid = XECKey.getAlgId(this.paramSpec.getCurve());

            if (h != null) {
                this.key = h.get().clone();
                this.h = Optional.of(this.key);
            }

            if (this.key == null) {
                this.xecKey = XECKey.generateKeyPair(provider.getOCKContext(),
                        this.paramSpec.getCurve());
            } else {
                this.algid = XECKey.getAlgId(this.paramSpec.getCurve());
                byte[] der = buildOCKPrivateKeyBytes();
                this.xecKey = XECKey.createPrivateKey(provider.getOCKContext(), der,
                        this.paramSpec.getCurve());
            }
        } catch (Exception exception) {
            InvalidParameterException ike = new InvalidParameterException(
                    "Failed to create XEC private key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
        checkLength(this.paramSpec);
    }

    public EdDSAPrivateKeyImpl(OpenJCEPlusProvider provider, byte[] encoded)
            throws InvalidKeyException, IOException {

        this.provider = provider;
        try {
            byte[] alteredEncoded = processEncodedPrivateKey(encoded); // Sets params, key, and algid, and alters encoded
            // to fit with GSKit and sets params

            checkLength(this.paramSpec);
            this.xecKey = XECKey.createPrivateKey(provider.getOCKContext(), alteredEncoded,
                    this.paramSpec.getCurve());

        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create XEC private key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
    }

    void checkLength(NamedParameterSpec params) throws InvalidKeyException {

        if (NamedParameterSpec.getPrivateCurveSize(params.getCurve()) != this.h.get().length) {
            throw new InvalidKeyException(
                    "key length is " + this.h.get().length + ", key length must be "
                            + NamedParameterSpec.getPrivateCurveSize(params.getCurve()));
        }
    }


    /**
     * Takes a DER encoded key of the following format: SEQUENCE: [version (INTEGER),
     * OID (OID is inside a sequence of 1 element), private key (OCTET STRING)]
     * Returns a similar DER with the last part of the sequence changed to:
     * OCTETSTRING[OCTETSTRING] (Octet string of an octet string which is the private key)
     * It's weird, no idea why it is this way but that's what GSKIT/OpenSSL accepts
     *
     * The function also sets the params field, algid, and key
     *
     * @param encoded
     * @return
     * @throws IOException
     */
    private byte[] processEncodedPrivateKey(byte[] encoded) throws IOException {
        DerInputStream in = new DerInputStream(encoded);
        DerValue[] inputValue = in.getSequence(3);
        DerOutputStream outStream = new DerOutputStream();

        // Copy version from input DER to new DER
        BigInteger version = inputValue[0].getBigInteger();
        outStream.putInteger(version);

        // Copy OID
        ObjectIdentifier oid = null;
        if (inputValue.length < 3)
            throw new IOException("This curve does not seem to be a valid EdDSA curve");

        if (inputValue[1].getTag() == DerValue.tag_Sequence) {
            DerInputStream oidInputStream = inputValue[1].toDerInputStream();
            DerOutputStream outputOIDSequence = new DerOutputStream();
            oid = processOIDSequence(oidInputStream, outputOIDSequence);
            this.algid = new AlgorithmId(oid);
            outStream.write(DerValue.tag_Sequence, outputOIDSequence.toByteArray());
        } else
            throw new IOException("Unexpected non sequence while parsing private key bytes");

        // Read, convert, then write private key
        this.key = inputValue[2].getOctetString(); // Get octet string
        //Need to remove seq tag from key
        this.key = Arrays.copyOfRange(this.key, 2, this.key.length);
        this.h = Optional.of(this.key);

        DerOutputStream encodedKey = new DerOutputStream();
        encodedKey.putOctetString(this.key); // Put in another octet string
        outStream.putOctetString(encodedKey.toByteArray());

        DerOutputStream asn1Key = new DerOutputStream();
        asn1Key.write(DerValue.tag_Sequence, outStream);

        return asn1Key.toByteArray();
    }

    /**
     * Takes a the OID Sequence part of a DER encoded key
     * Retrieves the curve type from that DER and sets the parameter
     * Retrieves and returns the OID
     * If output stream is present, put the OID to the output stream
     *
     * @param oidInputStream
     * @return objectIdentifer
     * @throws IOException
     */
    private ObjectIdentifier processOIDSequence(DerInputStream oidInputStream,
            DerOutputStream outStream) throws IOException {
        ObjectIdentifier oid = oidInputStream.getOID();
        XECKey.checkOid(oid);
        NamedParameterSpec.CURVE curve;
        curve = XECKey.getCurve(oid, null);

        if (outStream != null) {
            outStream.putOID(oid);
        }

        this.paramSpec = new NamedParameterSpec(curve);
        return oid;
    }

    /**
     * Extract and return the private key bytes from the output DER returned from GSKit.
     * The EdDSA privateKeyBytes format is SEQUENCE: [INTEGER (version), SEQUENCE[OID],
     * OCTET STRING[OCTET STRING(private key)]
     *
     * The function also sets the params field
     *
     * @param privateKeyBytes
     * @return
     * @throws IOException
     */
    private byte[] extractPrivateKeyFromOCK(byte[] privateKeyBytes) throws IOException {
        DerInputStream in = new DerInputStream(privateKeyBytes);
        DerValue[] inputValue = in.getSequence(3);
        // Retrieve OID and make sure its an EdDSA curve
        DerInputStream derInputStream = null;
        if (inputValue.length > 1) {
            derInputStream = inputValue[1].getData();
            try {
                processOIDSequence(derInputStream, null);
            } catch (Exception ex) {
                throw new IOException(
                        "This curve does not seem to be an EdDSA curve or correct OID", ex);
            }
        }

        // Private key is in the form of an octet string stored inside another octet string
        byte[] privData = null;
        if (inputValue.length > 2) {
            privData = inputValue[2].getOctetString();
            privData = new DerInputStream(privData).getOctetString();
            return privData;
        }
        return null;
    }

    /**
     * Builds DER from private key to be used to build EVP_PKEY in GSKit
     * DER form: SEQUENCE: SEQUENCE: [INTEGER (version), SEQUENCE[OID], OCTET STRING[OCTET STRING] (private key)
     *
     * @return
     * @throws IOException
     */
    private byte[] buildOCKPrivateKeyBytes() throws IOException {
        DerOutputStream mainSeq = new DerOutputStream();

        // Add first BigInteger (always 0 for EdDSA)
        mainSeq.putInteger(0);

        // Adding OID
        DerOutputStream oidSeq = new DerOutputStream();
        oidSeq.putOID(this.algid.getOID());
        mainSeq.write(DerValue.tag_Sequence, oidSeq.toByteArray());

        // Adding Key
        DerOutputStream keyOctetString = new DerOutputStream();
        keyOctetString.putOctetString(key);
        mainSeq.putOctetString(keyOctetString.toByteArray());

        // Wrapping up in a sequence
        DerOutputStream outStream = new DerOutputStream();
        outStream.write(DerValue.tag_Sequence, mainSeq);
        return outStream.toByteArray();
    }

    XECKey getOCKKey() {
        return this.xecKey;
    }

    @Override
    public java.security.spec.NamedParameterSpec getParams() {
        return this.paramSpec.getExternalParameter();
    }

    @Override
    public Optional<byte[]> getBytes() {
        try {
            setFieldsFromXeckey();
        } catch (Exception exception) {
            this.exception = exception;
        }
        return this.h;
    }

    @Override
    public AlgorithmId getAlgorithmId() {
        try {
            setFieldsFromXeckey();
        } catch (Exception exception) {
            this.exception = exception;
        }
        return super.getAlgorithmId();
    }

    @Override
    public byte[] getEncoded() {
        byte[] results = null;
        try {
            results = this.xecKey.getPrivateKeyBytes();
        } catch (Exception exception) {
            this.exception = exception;
        }
        return results;
    }

    @Override
    public String getAlgorithm() {
        try {
            setFieldsFromXeckey();
        } catch (Exception exception) {
            this.exception = exception;
        }

        return "EdDSA";
    }

    protected Object writeReplace() throws java.io.ObjectStreamException {
        return new KeyRep(KeyRep.Type.PRIVATE, getAlgorithm(), getFormat(), getEncoded());
    }
}

