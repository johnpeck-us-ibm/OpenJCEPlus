/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;

/**
 * Composite signature engine for draft-ietf-lamps-pq-composite-sigs.
 *
 * <p>Each composite algorithm pairs an ML-DSA component with a traditional
 * component (ECDSA, RSA-PSS, RSA-PKCS1 or EdDSA). Signing runs both engines
 * over the domain-separated message and returns:
 *
 * <pre>
 * CompositeSignatureValue ::= SEQUENCE SIZE (2) OF BIT STRING
 * </pre>
 *
 * <p>Verification decodes the SEQUENCE and succeeds only if <em>both</em>
 * component signatures are valid.
 *
 * <h2>Domain separation (draft §7)</h2>
 * <p>Before passing to each sub-engine the message is prepended with:
 * <pre>
 * M' = "CompositeAlgorithm" || 0x00 || DER(OID) || len(ctx) || ctx || message
 * </pre>
 * where {@code ctx} defaults to an empty byte array.
 */
@SuppressWarnings("restriction")
abstract class CompositeSignatureImpl extends SignatureSpi {

    private static final byte[] DOMAIN_PREFIX =
            "CompositeAlgorithm".getBytes(StandardCharsets.US_ASCII);

    private final OpenJCEPlusProvider provider;
    private final String compositeAlg;
    private final String mldsaSigAlg;
    private final String tradSigAlg;

    /** Buffered message bytes accumulated via {@code engineUpdate}. */
    private final ByteArrayOutputStream message = new ByteArrayOutputStream();

    private Signature mldsaSig;
    private Signature tradSig;
    private boolean initSign = false;
    private boolean initVerify = false;

    /**
     * @param provider     the OpenJCEPlus provider instance
     * @param compositeAlg the composite algorithm standard name
     * @param mldsaSigAlg  the JCA algorithm name for the ML-DSA Signature engine
     *                     (e.g. {@code "ML-DSA-44"})
     * @param tradSigAlg   the JCA algorithm name for the traditional Signature engine
     *                     (e.g. {@code "SHA256withECDSA"})
     */
    CompositeSignatureImpl(OpenJCEPlusProvider provider,
            String compositeAlg, String mldsaSigAlg, String tradSigAlg) {
        this.provider = provider;
        this.compositeAlg = compositeAlg;
        this.mldsaSigAlg = mldsaSigAlg;
        this.tradSigAlg = tradSigAlg;
        try {
            this.mldsaSig = Signature.getInstance(mldsaSigAlg, provider);
            this.tradSig = Signature.getInstance(tradSigAlg, provider);
        } catch (Exception e) {
            throw provider.providerException(
                    "Failed to initialize composite signature engines", e);
        }
    }

    // -----------------------------------------------------------------------
    // SignatureSpi implementation
    // -----------------------------------------------------------------------

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof CompositePrivateKey)) {
            throw new InvalidKeyException(
                    "Expected CompositePrivateKey, got: "
                            + privateKey.getClass().getName());
        }
        CompositePrivateKey ck = (CompositePrivateKey) privateKey;
        if (!compositeAlg.equalsIgnoreCase(ck.getAlgorithm())) {
            throw new InvalidKeyException(
                    "Key algorithm " + ck.getAlgorithm()
                            + " does not match signature algorithm " + compositeAlg);
        }
        try {
            PrivateKey mldsaKey = decodePrivateKey(mldsaSigAlg, ck.getMLDSAEncoded());
            PrivateKey tradKey = decodePrivateKey(tradSigAlg, ck.getTraditionalEncoded());
            mldsaSig.initSign(mldsaKey);
            tradSig.initSign(tradKey);
        } catch (Exception e) {
            throw new InvalidKeyException("Failed to initialize sign operation", e);
        }
        initSign = true;
        initVerify = false;
        message.reset();
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof CompositePublicKey)) {
            throw new InvalidKeyException(
                    "Expected CompositePublicKey, got: "
                            + publicKey.getClass().getName());
        }
        CompositePublicKey ck = (CompositePublicKey) publicKey;
        if (!compositeAlg.equalsIgnoreCase(ck.getAlgorithm())) {
            throw new InvalidKeyException(
                    "Key algorithm " + ck.getAlgorithm()
                            + " does not match signature algorithm " + compositeAlg);
        }
        try {
            PublicKey mldsaKey = decodePublicKey(mldsaSigAlg, ck.getMLDSAEncoded());
            PublicKey tradKey = decodePublicKey(tradSigAlg, ck.getTraditionalEncoded());
            mldsaSig.initVerify(mldsaKey);
            tradSig.initVerify(tradKey);
        } catch (Exception e) {
            throw new InvalidKeyException("Failed to initialize verify operation", e);
        }
        initSign = false;
        initVerify = true;
        message.reset();
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        message.write(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        message.write(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (!initSign) {
            throw new SignatureException("Signature not initialized for signing");
        }
        try {
            byte[] domainMsg = buildDomainSeparatedMessage(message.toByteArray());
            message.reset();

            mldsaSig.update(domainMsg);
            tradSig.update(domainMsg);

            byte[] mldsaSigBytes = mldsaSig.sign();
            byte[] tradSigBytes = tradSig.sign();

            return encodeCompositeSignature(mldsaSigBytes, tradSigBytes);
        } catch (IOException e) {
            throw new SignatureException("Failed to encode composite signature", e);
        } catch (Exception e) {
            throw new SignatureException("Composite sign failed", e);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (!initVerify) {
            throw new SignatureException("Signature not initialized for verification");
        }
        if (sigBytes == null) {
            return false;
        }
        try {
            byte[][] components = decodeCompositeSignature(sigBytes);
            byte[] mldsaSigBytes = components[0];
            byte[] tradSigBytes = components[1];

            byte[] domainMsg = buildDomainSeparatedMessage(message.toByteArray());
            message.reset();

            mldsaSig.update(domainMsg);
            tradSig.update(domainMsg);

            boolean mldsaOk = mldsaSig.verify(mldsaSigBytes);
            boolean tradOk = tradSig.verify(tradSigBytes);
            return mldsaOk && tradOk;
        } catch (Exception e) {
            return false;
        }
    }

    @Deprecated
    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new UnsupportedOperationException("getParameter() not supported");
    }

    @Deprecated
    @Override
    protected void engineSetParameter(String param, Object value)
            throws InvalidParameterException {
        throw new UnsupportedOperationException("setParameter() not supported");
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException(
                    "No parameters accepted for composite algorithm " + compositeAlg);
        }
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    // -----------------------------------------------------------------------
    // Domain separation (draft §7)
    // -----------------------------------------------------------------------

    /**
     * Builds the domain-separated message:
     * <pre>
     * M' = "CompositeAlgorithm" || 0x00 || DER(OID) || 0x00 || message
     * </pre>
     *
     * <p>The context string ({@code ctx}) is fixed to the empty byte array
     * per the default specified in §7 of the draft.
     */
    private byte[] buildDomainSeparatedMessage(byte[] msg) throws IOException {
        // Encode the OID as a DER TLV (tag 0x06 + length + content)
        DerOutputStream oidOut = new DerOutputStream();
        oidOut.putOID(CompositeAlgorithmId.getOID(compositeAlg));
        byte[] oidDer = oidOut.toByteArray();

        ByteArrayOutputStream buf = new ByteArrayOutputStream(
                DOMAIN_PREFIX.length + 1 + oidDer.length + 1 + msg.length);
        buf.write(DOMAIN_PREFIX);
        buf.write(0x00); // separator
        buf.write(oidDer);
        buf.write(0x00); // len(ctx) = 0 (empty context)
        buf.write(msg);
        return buf.toByteArray();
    }

    // -----------------------------------------------------------------------
    // Composite signature encoding / decoding
    // -----------------------------------------------------------------------

    /**
     * Encodes the two component signature bytes as:
     * <pre>
     * CompositeSignatureValue ::= SEQUENCE SIZE (2) OF BIT STRING
     * </pre>
     */
    private static byte[] encodeCompositeSignature(byte[] mldsaSig, byte[] tradSig)
            throws IOException {
        DerOutputStream inner = new DerOutputStream();
        inner.putBitString(mldsaSig);
        inner.putBitString(tradSig);

        DerOutputStream out = new DerOutputStream();
        out.write(DerValue.tag_Sequence, inner);
        return out.toByteArray();
    }

    /**
     * Decodes a {@code CompositeSignatureValue SEQUENCE SIZE (2) OF BIT STRING}.
     *
     * @return two-element array {@code {mldsaSigBytes, tradSigBytes}}
     * @throws SignatureException if the encoding is malformed
     */
    private static byte[][] decodeCompositeSignature(byte[] encoded)
            throws SignatureException {
        try {
            DerValue seq = new DerValue(encoded);
            if (seq.tag != DerValue.tag_Sequence) {
                throw new SignatureException(
                        "CompositeSignatureValue is not a SEQUENCE");
            }
            byte[] mldsa = seq.data.getBitString();
            byte[] trad = seq.data.getBitString();
            return new byte[][] {mldsa, trad};
        } catch (IOException e) {
            throw new SignatureException(
                    "Failed to decode composite signature", e);
        }
    }

    // -----------------------------------------------------------------------
    // Key helpers
    // -----------------------------------------------------------------------

    /**
     * Decodes a PKCS#8 byte array into a PrivateKey using the JCA algorithm
     * name of the component (resolved to a KeyFactory algorithm string).
     */
    private PrivateKey decodePrivateKey(String sigAlg, byte[] pkcs8Bytes)
            throws Exception {
        String kfAlg = keyFactoryAlg(sigAlg);
        java.security.KeyFactory kf =
                java.security.KeyFactory.getInstance(kfAlg, provider);
        return kf.generatePrivate(
                new java.security.spec.PKCS8EncodedKeySpec(pkcs8Bytes));
    }

    /**
     * Decodes an X.509 byte array into a PublicKey using the JCA algorithm
     * name of the component (resolved to a KeyFactory algorithm string).
     */
    private PublicKey decodePublicKey(String sigAlg, byte[] x509Bytes)
            throws Exception {
        String kfAlg = keyFactoryAlg(sigAlg);
        java.security.KeyFactory kf =
                java.security.KeyFactory.getInstance(kfAlg, provider);
        return kf.generatePublic(
                new java.security.spec.X509EncodedKeySpec(x509Bytes));
    }

    /**
     * Maps a Signature algorithm name to the corresponding KeyFactory algorithm
     * name.  For example {@code "SHA256withECDSA"} → {@code "EC"}.
     */
    private static String keyFactoryAlg(String sigAlg) {
        String up = sigAlg.toUpperCase(java.util.Locale.ROOT);
        if (up.contains("ECDSA") || up.startsWith("EC")) {
            return "EC";
        }
        if (up.contains("RSA")) {
            return "RSA";
        }
        if (up.startsWith("ED25519") || up.equals("ED25519")) {
            return "Ed25519";
        }
        if (up.startsWith("ED448") || up.equals("ED448")) {
            return "Ed448";
        }
        // For ML-DSA component: sigAlg IS the key alg (e.g. "ML-DSA-44")
        return sigAlg;
    }

    // -----------------------------------------------------------------------
    // Concrete inner classes — one per composite algorithm combination
    // -----------------------------------------------------------------------

    public static final class MLDSA44RSA2048PSSSHA256 extends CompositeSignatureImpl {
        public MLDSA44RSA2048PSSSHA256(OpenJCEPlusProvider p) {
            super(p, "MLDSA44-RSA2048-PSS-SHA256", "ML-DSA-44", "SHA256withRSASSA-PSS");
        }
    }

    public static final class MLDSA44RSA2048PKCS15SHA256 extends CompositeSignatureImpl {
        public MLDSA44RSA2048PKCS15SHA256(OpenJCEPlusProvider p) {
            super(p, "MLDSA44-RSA2048-PKCS15-SHA256", "ML-DSA-44", "SHA256withRSA");
        }
    }

    public static final class MLDSA44Ed25519 extends CompositeSignatureImpl {
        public MLDSA44Ed25519(OpenJCEPlusProvider p) {
            super(p, "MLDSA44-Ed25519", "ML-DSA-44", "Ed25519");
        }
    }

    public static final class MLDSA44ECDSAP256SHA256 extends CompositeSignatureImpl {
        public MLDSA44ECDSAP256SHA256(OpenJCEPlusProvider p) {
            super(p, "MLDSA44-ECDSA-P256-SHA256", "ML-DSA-44", "SHA256withECDSA");
        }
    }

    public static final class MLDSA65RSA3072PSSSHA512 extends CompositeSignatureImpl {
        public MLDSA65RSA3072PSSSHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA65-RSA3072-PSS-SHA512", "ML-DSA-65", "SHA512withRSASSA-PSS");
        }
    }

    public static final class MLDSA65RSA3072PKCS15SHA512 extends CompositeSignatureImpl {
        public MLDSA65RSA3072PKCS15SHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA65-RSA3072-PKCS15-SHA512", "ML-DSA-65", "SHA512withRSA");
        }
    }

    public static final class MLDSA65ECDSAP384SHA384 extends CompositeSignatureImpl {
        public MLDSA65ECDSAP384SHA384(OpenJCEPlusProvider p) {
            super(p, "MLDSA65-ECDSA-P384-SHA384", "ML-DSA-65", "SHA384withECDSA");
        }
    }

    public static final class MLDSA65Ed25519 extends CompositeSignatureImpl {
        public MLDSA65Ed25519(OpenJCEPlusProvider p) {
            super(p, "MLDSA65-Ed25519", "ML-DSA-65", "Ed25519");
        }
    }

    public static final class MLDSA87ECDSAP384SHA384 extends CompositeSignatureImpl {
        public MLDSA87ECDSAP384SHA384(OpenJCEPlusProvider p) {
            super(p, "MLDSA87-ECDSA-P384-SHA384", "ML-DSA-87", "SHA384withECDSA");
        }
    }

    public static final class MLDSA87ECDSAP521SHA512 extends CompositeSignatureImpl {
        public MLDSA87ECDSAP521SHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA87-ECDSA-P521-SHA512", "ML-DSA-87", "SHA512withECDSA");
        }
    }

    public static final class MLDSA87Ed448 extends CompositeSignatureImpl {
        public MLDSA87Ed448(OpenJCEPlusProvider p) {
            super(p, "MLDSA87-Ed448", "ML-DSA-87", "Ed448");
        }
    }
}
