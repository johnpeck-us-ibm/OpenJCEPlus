/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.PQCKey;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import javax.security.auth.DestroyFailedException;
import sun.security.pkcs.PKCS8Key;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X509Key;

/*
 * A PQC private key for the NIST FIPS 203 Algorithm.
 */
@SuppressWarnings("restriction")
final class PQCPrivateKey extends PKCS8Key {

    private static final long serialVersionUID = -3168962080315231494L;

    private OpenJCEPlusProvider provider = null;
    private final String name;
    private byte[] attributes = null;

    private transient PQCKey pqcKey;

    private transient boolean destroyed = false;

    /**
     * Create a MLKEM private key from the parameters and key data.
     *
     * @param keyBytes
     *                the private key bytes used to decapsulate a secret key
     */
    public PQCPrivateKey(OpenJCEPlusProvider provider, byte[] keyBytes, String algName)
            throws InvalidKeyException {
   
        this.algid = new AlgorithmId(PQCAlgorithmId.getOID(algName));
        this.name = algName;
        this.provider = provider;
        byte [] key = null;
        DerValue pkOct = null;
        
        //Check to determine if the key bytes already have the Octet tag.
        if (OctectStringEncoded(keyBytes)) {
            //Remove encoding OctetString encoding.
            key = Arrays.copyOfRange(keyBytes, 4, keyBytes.length);
        } else {            
            key = keyBytes;
        }

        // Currently the ICC expects the raw keys in an OctetString
        try {  
            try {
                pkOct = new DerValue(DerValue.tag_OctetString, key);
     
                this.pqcKey = PQCKey.createPrivateKey(provider.getOCKContext(), 
                                   this.name, pkOct.toByteArray());
                this.privKeyMaterial = pkOct.toByteArray();
            } finally {
                pkOct.clear();
            }
        } catch (Exception e) {
            throw new InvalidKeyException("Invalid key " + e.getMessage(), e);
        }   
    }

    /**
     * Create a ML_KEM private key from it's DER encoding (PKCS#8)
     *
     * @param encoded
     *                the encoded parameters.
     */
    public PQCPrivateKey(OpenJCEPlusProvider provider, PQCKey pqcKey) throws InvalidKeyException {
        try {
            this.provider = provider;
            this.pqcKey = pqcKey;

            this.name = pqcKey.getAlgorithm();
            this.algid = new AlgorithmId(PQCAlgorithmId.getOID(name));

            if (!(this.name.startsWith("SLH-DSA"))) {
               //Check to determine if the key bytes have the Octet tag.
               if (OctectStringEncoded(pqcKey.getPrivateKeyBytes())) {
                    this.privKeyMaterial = pqcKey.getPrivateKeyBytes();
                } else {
                    DerValue pkOct = null;
                    try {
                        pkOct = new DerValue(DerValue.tag_OctetString, pqcKey.getPrivateKeyBytes());

                        this.privKeyMaterial = pkOct.toByteArray();
                    } finally {
                        pkOct.clear();
                    }
                }
            } else {
                //Extract the private key info from the generated key.
                decode(new DerValue(pqcKey.getPrivateKeyBytes()));
            }

        } catch (Exception exception) {
            throw provider.providerException("Failure in PQCPrivateKey" + exception.getMessage(), exception);
        }
    }

    /**
     * Create a private key from it's DER encoding (PKCS#8)
     *
     * @param encoded
     *                the encoded parameters.
     */
    public PQCPrivateKey(OpenJCEPlusProvider provider, byte[] encoded) throws InvalidKeyException {
        //super(encoded);
        try {
            decode(new DerValue(encoded));
        } catch (Exception e) {
            throw new InvalidKeyException("Invalid key " + e.getMessage(), e);
        }
        this.provider = provider;

        this.name = PQCKnownOIDs.findMatch(this.algid.getName()).stdName();
        
        if (!(this.name.startsWith("SLH-DSA"))) {
            //Check to determine if the key bytes have the Octet tag.      
            if (!(OctectStringEncoded(this.privKeyMaterial))) {
                DerValue pkOct = null;
                try {
                    pkOct = new DerValue(DerValue.tag_OctetString, this.privKeyMaterial);

                    this.privKeyMaterial = pkOct.toByteArray();
                } finally {
                    pkOct.clear();
                }
            }
            try {
                this.pqcKey = PQCKey.createPrivateKey(provider.getOCKContext(), 
                                   this.name, this.privKeyMaterial);
            } catch (Exception e) {
                throw new InvalidKeyException("Invalid key " + e.getMessage(), e);
            }  
        } else {
            try {
                this.pqcKey = PQCKey.createPrivateKey(provider.getOCKContext(), 
                                   this.name, getEncoded());
            } catch (Exception e) {
                throw new InvalidKeyException("Invalid key " + e.getMessage(), e);
            }  
        }
    }

    @Override
    public String getAlgorithm() {
        checkDestroyed();
        return name;
    }

    private void decode(DerValue val) throws InvalidKeyException {
        /*
        *     OneAsymmetricKey ::= SEQUENCE {
        *        version                   Version,
        *        privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
        *        privateKey                PrivateKey,
        *        attributes            [0] Attributes OPTIONAL,
        *        ...,
        *        [[2: publicKey        [1] PublicKey OPTIONAL ]],
        *        ...
        *      }
        */
        try {
            if (val.tag != DerValue.tag_Sequence) {
                throw new InvalidKeyException("invalid key format");
            }

            // Support check for V1, aka 0, and V2, aka 1.
            int ver = val.data.getInteger();
            if (ver != 0 && ver != 1) {
                throw new InvalidKeyException("unknown version: " + ver);
            }
            // Parse and store AlgorithmID
            algid = AlgorithmId.parse(val.data.getDerValue());

            // Store key material for subclasses to parse
            this.privKeyMaterial = val.data.getOctetString();

            // v1 typically ends here
            if (val.data.available() == 0) {
                return;
            }

            // OPTIONAL Context tag 0 for Attributes
            // Uses 0xA0 context-specific/constructed or 0x80
            // context-specific/primitive.
            DerValue v = val.data.getDerValue();
            if (v.isContextSpecific((byte)0)) {
                attributes = v.getDataBytes(); 
                if (val.data.available() == 0) {
                    return;
                }
                v = val.data.getDerValue();
            }

            // OPTIONAL context tag 1 for Public Key
            if (ver == 1) {
                if (v.isContextSpecific((byte)1)) {
                    DerValue bits = v.withTag(DerValue.tag_BitString);
                    this.pubKeyEncoded = new X509Key(algid,
                        bits.getUnalignedBitString()).getEncoded();
                } else {
                    throw new InvalidKeyException("Invalid context tag");
                }
                if (val.data.available() == 0) {
                    return;
                }
            }

            throw new InvalidKeyException("Extra bytes");
        } catch (IOException e) {
            throw new InvalidKeyException("Unable to decode key", e);
        } finally {
            if (val != null) {
                val.clear();
            }
        }
    }

    @Override
    public byte[] getEncoded() {
        checkDestroyed();
        /*Different JVM levels are resulting in different encodings. So do the encoding here instead.
        *     OneAsymmetricKey ::= SEQUENCE {
        *        version                   Version,
        *        privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
        *        privateKey                PrivateKey,
        *        attributes            [0] Attributes OPTIONAL,
        *        ...,
        *        [[2: publicKey        [1] PublicKey OPTIONAL ]],
        *        ...
        *      }
        */
        byte [] encodedKey = null;
        try {
            int V1 = 0;
            DerOutputStream tmp = new DerOutputStream();
            tmp.putInteger(V1);
            DerOutputStream bytes = new DerOutputStream();
            bytes.putOID(algid.getOID());
            tmp.write(DerValue.tag_Sequence, bytes);
            tmp.putOctetString(this.privKeyMaterial);
            DerValue out = DerValue.wrap(DerValue.tag_Sequence, tmp);
            encodedKey = out.toByteArray();
            tmp.close();
            bytes.close();
        } catch (IOException ex) {
            return encodedKey;
        }
        
        return encodedKey;
    }

    PQCKey getPQCKey() {
        return this.pqcKey;
    }

    /**
     * Destroys this key. A call to any of its other methods after this will
     * cause an IllegalStateException to be thrown.
     *
     * @throws DestroyFailedException
     *                                if some error occurs while destroying this
     *                                key.
     */
    @Override
    public void destroy() throws DestroyFailedException {
        if (!destroyed) {
            destroyed = true;
            Arrays.fill(this.privKeyMaterial, 0, this.privKeyMaterial.length, (byte)0x00);
            this.privKeyMaterial = null;
            this.encodedKey = null;
            this.pqcKey = null;
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

    private boolean OctectStringEncoded(byte [] key) {
        try {
            //Check and see if this is an encoded OctetString
            if (key[0] == 0x04) {
                //This might be encoded
                StringBuilder sb = new StringBuilder();
                for (int i = 2; i < 4; i++) {
                    sb.append(String.format("%02X", key[i]));
                }
                String s =sb.toString();
                int b =  Integer.parseInt(s,16);
                if (b == (key.length - 4)) {
                    //This is an encoding
                    return true;
                }
            } 
            return false;
        } catch (Exception e) {              
            return false;
        }    
    }

}
