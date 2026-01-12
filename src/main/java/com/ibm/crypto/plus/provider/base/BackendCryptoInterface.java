/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

/**
 * BackendCryptoInterface defines the contract for cryptographic backend implementations.
 * This interface abstracts the native cryptographic operations, allowing different
 * backends (OCK, OpenSSL) to provide their own implementations.
 */
public interface BackendCryptoInterface {

    /**
     * Initializes the backend. This method should be called once before any other operations.
     * 
     * @throws OCKException if initialization fails
     */
    void initialize() throws OCKException;

    // =========================================================================
    // Random number generator functions
    // =========================================================================

    void RAND_nextBytes(boolean isFIPS, byte[] buffer) throws OCKException;

    void RAND_setSeed(boolean isFIPS, byte[] seed) throws OCKException;

    void RAND_generateSeed(boolean isFIPS, byte[] seed) throws OCKException;

    // =========================================================================
    // Extended random number generator functions
    // =========================================================================

    long EXTRAND_create(boolean isFIPS, String algName) throws OCKException;

    void EXTRAND_nextBytes(boolean isFIPS, long ockPRNGContextId, byte[] buffer) throws OCKException;

    void EXTRAND_setSeed(boolean isFIPS, long ockPRNGContextId, byte[] seed) throws OCKException;

    void EXTRAND_delete(boolean isFIPS, long ockPRNGContextId) throws OCKException;

    // =========================================================================
    // Cipher functions
    // =========================================================================

    long CIPHER_create(boolean isFIPS, String cipher) throws OCKException;

    void CIPHER_init(boolean isFIPS, long ockCipherId, int isEncrypt, int paddingId, byte[] key, byte[] iv) throws OCKException;

    void CIPHER_clean(boolean isFIPS, long ockCipherId) throws OCKException;

    void CIPHER_setPadding(boolean isFIPS, long ockCipherId, int paddingId) throws OCKException;

    int CIPHER_getBlockSize(boolean isFIPS, long ockCipherId);

    int CIPHER_getKeyLength(boolean isFIPS, long ockCipherId);

    int CIPHER_getIVLength(boolean isFIPS, long ockCipherId);

    int CIPHER_getOID(boolean isFIPS, long ockCipherId);

    int CIPHER_encryptUpdate(boolean isFIPS, long ockCipherId, byte[] plaintext, int plaintextOffset, int plaintextLen, byte[] ciphertext, int ciphertextOffset, boolean needsReinit) throws OCKException;

    int CIPHER_decryptUpdate(boolean isFIPS, long ockCipherId, byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext, int plaintextOffset, boolean needsReinit) throws OCKException;

    int CIPHER_encryptFinal(boolean isFIPS, long ockCipherId, byte[] input, int inOffset, int inLen, byte[] ciphertext, int ciphertextOffset, boolean needsReinit) throws OCKException;

    int CIPHER_decryptFinal(boolean isFIPS, long ockCipherId, byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext, int plaintextOffset, boolean needsReinit) throws OCKException;

    long checkHardwareSupport(boolean isFIPS);

    void CIPHER_delete(boolean isFIPS, long ockCipherId) throws OCKException;

    byte[] CIPHER_KeyWraporUnwrap(boolean isFIPS, byte[] key, byte[] KEK, int type) throws OCKException;

    int z_kmc_native(byte[] input, int inputOffset, byte[] output, int outputOffset, long paramPointer, int inputLength, int mode);

    // =========================================================================
    // Poly1305 Cipher functions
    // =========================================================================

    long POLY1305CIPHER_create(boolean isFIPS, String cipher) throws OCKException;

    void POLY1305CIPHER_init(boolean isFIPS, long ockCipherId, int isEncrypt, byte[] key, byte[] iv) throws OCKException;

    void POLY1305CIPHER_clean(boolean isFIPS, long ockCipherId) throws OCKException;

    void POLY1305CIPHER_setPadding(boolean isFIPS, long ockCipherId, int paddingId) throws OCKException;

    int POLY1305CIPHER_getBlockSize(boolean isFIPS, long ockCipherId);

    int POLY1305CIPHER_getKeyLength(boolean isFIPS, long ockCipherId);

    int POLY1305CIPHER_getIVLength(boolean isFIPS, long ockCipherId);

    int POLY1305CIPHER_getOID(boolean isFIPS, long ockCipherId);

    int POLY1305CIPHER_encryptUpdate(boolean isFIPS, long ockCipherId, byte[] plaintext, int plaintextOffset, int plaintextLen, byte[] ciphertext, int ciphertextOffset) throws OCKException;

    int POLY1305CIPHER_decryptUpdate(boolean isFIPS, long ockCipherId, byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext, int plaintextOffset) throws OCKException;

    int POLY1305CIPHER_encryptFinal(boolean isFIPS, long ockCipherId, byte[] input, int inOffset, int inLen, byte[] ciphertext, int ciphertextOffset, byte[] tag) throws OCKException;

    int POLY1305CIPHER_decryptFinal(boolean isFIPS, long ockCipherId, byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext, int plaintextOffset, byte[] tag) throws OCKException;

    void POLY1305CIPHER_delete(boolean isFIPS, long ockCipherId) throws OCKException;

    // =========================================================================
    // GCM Cipher functions
    // =========================================================================

    long do_GCM_checkHardwareGCMSupport(boolean isFIPS);

    int do_GCM_encryptFastJNI_WithHardwareSupport(int keyLen, int ivLen, int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen, long parameterBuffer, byte[] input, int inputOffset, byte[] output, int outputOffset) throws OCKException;

    int do_GCM_encryptFastJNI(boolean isFIPS, long gcmCtx, int keyLen, int ivLen, int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen, long parameterBuffer, long inputBuffer, long outputBuffer) throws OCKException;

    int do_GCM_decryptFastJNI_WithHardwareSupport(int keyLen, int ivLen, int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen, long parameterBuffer, byte[] input, int inputOffset, byte[] output, int outputOffset) throws OCKException;

    int do_GCM_decryptFastJNI(boolean isFIPS, long gcmCtx, int keyLen, int ivLen, int ciphertextOffset, int ciphertextLen, int plainOffset, int aadLen, int tagLen, long parameterBuffer, long inputBuffer, long outputBuffer) throws OCKException;

    int do_GCM_encrypt(boolean isFIPS, long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] input, int inOffset, int inLen, byte[] ciphertext, int ciphertextOffset, byte[] aad, int aadLen, byte[] tag, int tagLen) throws OCKException;

    int do_GCM_decrypt(boolean isFIPS, long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext, int plaintextOffset, byte[] aad, int aadLen, int tagLen) throws OCKException;

    int do_GCM_FinalForUpdateEncrypt(boolean isFIPS, long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] input, int inOffset, int inLen, byte[] ciphertext, int ciphertextOffset, byte[] aad, int aadLen, byte[] tag, int tagLen) throws OCKException;

    int do_GCM_FinalForUpdateDecrypt(boolean isFIPS, long gcmCtx, byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext, int plaintextOffset, int plaintextlen, byte[] aad, int aadLen, int tagLen) throws OCKException;

    int do_GCM_UpdForUpdateEncrypt(boolean isFIPS, long gcmCtx, byte[] input, int inOffset, int inLen, byte[] ciphertext, int ciphertextOffset) throws OCKException;

    int do_GCM_UpdForUpdateDecrypt(boolean isFIPS, long gcmCtx, byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext, int plaintextOffset) throws OCKException;

    int do_GCM_InitForUpdateEncrypt(boolean isFIPS, long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] aad, int aadLen) throws OCKException;

    int do_GCM_InitForUpdateDecrypt(boolean isFIPS, long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] aad, int aadLen) throws OCKException;

    void do_GCM_delete(boolean isFIPS) throws OCKException;

    void free_GCM_ctx(boolean isFIPS, long gcmContextId) throws OCKException;

    long create_GCM_context(boolean isFIPS) throws OCKException;

    // =========================================================================
    // CCM Cipher functions
    // =========================================================================

    long do_CCM_checkHardwareCCMSupport(boolean isFIPS);

    int do_CCM_encryptFastJNI_WithHardwareSupport(int keyLen, int ivLen, int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen, long parameterBuffer, byte[] input, int inputOffset, byte[] output, int outputOffset) throws OCKException;

    int do_CCM_encryptFastJNI(boolean isFIPS, int keyLen, int ivLen, int inLen, int ciphertextLen, int aadLen, int tagLen, long parameterBuffer, long inputBuffer, long outputBuffer) throws OCKException;

    int do_CCM_decryptFastJNI_WithHardwareSupport(int keyLen, int ivLen, int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen, long parameterBuffer, byte[] input, int inputOffset, byte[] output, int outputOffset) throws OCKException;

    int do_CCM_decryptFastJNI(boolean isFIPS, int keyLen, int ivLen, int ciphertextLen, int plaintextLen, int aadLen, int tagLen, long parameterBuffer, long inputBuffer, long outputBuffer) throws OCKException;

    int do_CCM_encrypt(boolean isFIPS, byte[] iv, int ivLen, byte[] key, int keyLen, byte[] aad, int aadLen, byte[] input, int inLen, byte[] ciphertext, int ciphertextLen, int tagLen) throws OCKException;

    int do_CCM_decrypt(boolean isFIPS, byte[] iv, int ivLen, byte[] key, int keyLen, byte[] aad, int aadLen, byte[] ciphertext, int ciphertextLength, byte[] plaintext, int plaintextLength, int tagLen) throws OCKException;

    void do_CCM_delete(boolean isFIPS) throws OCKException;

    // =========================================================================
    // RSA cipher functions
    // =========================================================================

    int RSACIPHER_public_encrypt(boolean isFIPS, long rsaKeyId, int rsaPaddingId, int mdId, int mgf1Id, byte[] plaintext, int plaintextOffset, int plaintextLen, byte[] ciphertext, int ciphertextOffset) throws OCKException;

    int RSACIPHER_private_encrypt(boolean isFIPS, long rsaKeyId, int rsaPaddingId, byte[] plaintext, int plaintextOffset, int plaintextLen, byte[] ciphertext, int ciphertextOffset, boolean convertKey) throws OCKException;

    int RSACIPHER_public_decrypt(boolean isFIPS, long rsaKeyId, int rsaPaddingId, byte[] ciphertext, int ciphertextOffset, int ciphertextLen, byte[] plaintext, int plaintextOffset) throws OCKException;

    int RSACIPHER_private_decrypt(boolean isFIPS, long rsaKeyId, int rsaPaddingId, int mdId, int mgf1Id, byte[] ciphertext, int ciphertextOffset, int ciphertextLen, byte[] plaintext, int plaintextOffset, boolean convertKey) throws OCKException;

    // =========================================================================
    // DH key functions
    // =========================================================================

    long DHKEY_generate(boolean isFIPS, int numBits) throws OCKException;

    byte[] DHKEY_generateParameters(boolean isFIPS, int numBits);

    long DHKEY_generate(boolean isFIPS, byte[] dhParameters) throws OCKException;

    long DHKEY_createPrivateKey(boolean isFIPS, byte[] privateKeyBytes) throws OCKException;

    long DHKEY_createPublicKey(boolean isFIPS, byte[] publicKeyBytes) throws OCKException;

    byte[] DHKEY_getParameters(boolean isFIPS, long dhKeyId);

    byte[] DHKEY_getPrivateKeyBytes(boolean isFIPS, long dhKeyId) throws OCKException;

    byte[] DHKEY_getPublicKeyBytes(boolean isFIPS, long dhKeyId) throws OCKException;

    long DHKEY_createPKey(boolean isFIPS, long dhKeyId) throws OCKException;

    byte[] DHKEY_computeDHSecret(boolean isFIPS, long pubKeyId, long privKeyId) throws OCKException;

    void DHKEY_delete(boolean isFIPS, long dhKeyId) throws OCKException;

    // =========================================================================
    // RSA key functions
    // =========================================================================

    long RSAKEY_generate(boolean isFIPS, int numBits, long e) throws OCKException;

    long RSAKEY_createPrivateKey(boolean isFIPS, byte[] privateKeyBytes) throws OCKException;

    long RSAKEY_createPublicKey(boolean isFIPS, byte[] publicKeyBytes) throws OCKException;

    byte[] RSAKEY_getPrivateKeyBytes(boolean isFIPS, long rsaKeyId) throws OCKException;

    byte[] RSAKEY_getPublicKeyBytes(boolean isFIPS, long rsaKeyId) throws OCKException;

    int RSAKEY_size(boolean isFIPS, long rsaKeyId);

    void RSAKEY_delete(boolean isFIPS, long rsaKeyId);

    // =========================================================================
    // DSA key functions
    // =========================================================================

    long DSAKEY_generate(boolean isFIPS, int numBits) throws OCKException;

    byte[] DSAKEY_generateParameters(boolean isFIPS, int numBits);

    long DSAKEY_generate(boolean isFIPS, byte[] dsaParameters) throws OCKException;

    long DSAKEY_createPrivateKey(boolean isFIPS, byte[] privateKeyBytes) throws OCKException;

    long DSAKEY_createPublicKey(boolean isFIPS, byte[] publicKeyBytes) throws OCKException;

    byte[] DSAKEY_getParameters(boolean isFIPS, long dsaKeyId);

    byte[] DSAKEY_getPrivateKeyBytes(boolean isFIPS, long dsaKeyId) throws OCKException;

    byte[] DSAKEY_getPublicKeyBytes(boolean isFIPS, long dsaKeyId) throws OCKException;

    long DSAKEY_createPKey(boolean isFIPS, long dsaKeyId) throws OCKException;

    void DSAKEY_delete(boolean isFIPS, long dsaKeyId) throws OCKException;

    // =========================================================================
    // PKey functions
    // =========================================================================

    void PKEY_delete(boolean isFIPS, long pkeyId) throws OCKException;

    // =========================================================================
    // Digest functions
    // =========================================================================

    long DIGEST_create(boolean isFIPS, String digestAlgo) throws OCKException;

    long DIGEST_copy(long id, long digestId) throws OCKException;

    int DIGEST_update(boolean isFIPS, long digestId, byte[] input, int offset, int length) throws OCKException;

    void DIGEST_updateFastJNI(boolean isFIPS, long digestId, long inputBuffer, int length) throws OCKException;

    byte[] DIGEST_digest(boolean isFIPS, long digestId) throws OCKException;

    void DIGEST_digest_and_reset(boolean isFIPS, long digestId, long outputBuffer, int length) throws OCKException;

    int DIGEST_digest_and_reset(boolean isFIPS, long digestId, byte[] output) throws OCKException;

    int DIGEST_size(boolean isFIPS, long digestId) throws OCKException;

    void DIGEST_reset(boolean isFIPS, long digestId) throws OCKException;

    void DIGEST_delete(boolean isFIPS, long digestId) throws OCKException;

    int DIGEST_PKCS12KeyDeriveHelp(boolean isFIPS, long digestId, byte[] input, int offset, int length, int iterationCount) throws OCKException;

    // =========================================================================
    // Signature functions (with digest)
    // =========================================================================

    byte[] SIGNATURE_sign(boolean isFIPS, long digestId, long pkeyId, boolean convert) throws OCKException;

    boolean SIGNATURE_verify(boolean isFIPS, long digestId, long pkeyId, byte[] sigBytes) throws OCKException;

    byte[] SIGNATUREEdDSA_signOneShot(boolean isFIPS, long pkeyId, byte[] bytes) throws OCKException;

    boolean SIGNATUREEdDSA_verifyOneShot(boolean isFIPS, long pkeyId, byte[] sigBytes, byte[] oneShot) throws OCKException;

    // =========================================================================
    // RSAPSSSignature functions
    // =========================================================================

    int RSAPSS_signInit(boolean isFIPS, long rsaPssId, long pkeyId, int saltlen, boolean convert) throws OCKException;

    int RSAPSS_verifyInit(boolean isFIPS, long rsaPssId, long pkeyId, int saltlen) throws OCKException;

    int RSAPSS_getSigLen(boolean isFIPS, long rsaPssId);

    void RSAPSS_signFinal(boolean isFIPS, long rsaPssId, byte[] signature, int length) throws OCKException;

    boolean RSAPSS_verifyFinal(boolean isFIPS, long rsaPssId, byte[] sigBytes, int length) throws OCKException;

    long RSAPSS_createContext(boolean isFIPS, String digestAlgo, String mgf1SpecAlgo) throws OCKException;

    void RSAPSS_releaseContext(boolean isFIPS, long rsaPssId) throws OCKException;

    void RSAPSS_digestUpdate(boolean isFIPS, long rsaPssId, byte[] input, int offset, int length) throws OCKException;

    void RSAPSS_reset(boolean isFIPS, long digestId) throws OCKException;

    void RSAPSS_resetDigest(boolean isFIPS, long rsaPssId) throws OCKException;

    // =========================================================================
    // DSA Signature functions (pre-hashed data)
    // =========================================================================

    byte[] DSANONE_SIGNATURE_sign(boolean isFIPS, byte[] digest, long dsaKeyId) throws OCKException;

    boolean DSANONE_SIGNATURE_verify(boolean isFIPS, byte[] digest, long dsaKeyId, byte[] sigBytes) throws OCKException;

    // =========================================================================
    // RSASSL Signature functions (pre-hashed data)
    // =========================================================================

    byte[] RSASSL_SIGNATURE_sign(boolean isFIPS, byte[] digest, long rsaKeyId) throws OCKException;

    boolean RSASSL_SIGNATURE_verify(boolean isFIPS, byte[] digest, long rsaKeyId, byte[] sigBytes, boolean convert) throws OCKException;

    // =========================================================================
    // HMAC functions
    // =========================================================================

    long HMAC_create(boolean isFIPS, String digestAlgo) throws OCKException;

    int HMAC_update(boolean isFIPS, long hmacId, byte[] key, int keyLength, byte[] input, int inputOffset, int inputLength, boolean needInit) throws OCKException;

    int HMAC_doFinal(boolean isFIPS, long hmacId, byte[] key, int keyLength, byte[] hmac, boolean needInit) throws OCKException;

    int HMAC_size(boolean isFIPS, long hmacId) throws OCKException;

    void HMAC_delete(boolean isFIPS, long hmacId) throws OCKException;

    // =========================================================================
    // EC key functions
    // =========================================================================

    long ECKEY_generate(boolean isFIPS, int numBits) throws OCKException;

    long ECKEY_generate(boolean isFIPS, String curveOid) throws OCKException;

    long XECKEY_generate(boolean isFIPS, int option, long bufferPtr) throws OCKException;

    byte[] ECKEY_generateParameters(boolean isFIPS, int numBits) throws OCKException;

    byte[] ECKEY_generateParameters(boolean isFIPS, String curveOid) throws OCKException;

    long ECKEY_generate(boolean isFIPS, byte[] ecParameters) throws OCKException;

    long ECKEY_createPrivateKey(boolean isFIPS, byte[] privateKeyBytes) throws OCKException;

    long XECKEY_createPrivateKey(boolean isFIPS, byte[] privateKeyBytes, long bufferPtr) throws OCKException;

    long ECKEY_createPublicKey(boolean isFIPS, byte[] publicKeyBytes, byte[] parameterBytes) throws OCKException;

    long XECKEY_createPublicKey(boolean isFIPS, byte[] publicKeyBytes) throws OCKException;

    byte[] ECKEY_getParameters(boolean isFIPS, long ecKeyId);

    byte[] ECKEY_getPrivateKeyBytes(boolean isFIPS, long ecKeyId) throws OCKException;

    byte[] XECKEY_getPrivateKeyBytes(boolean isFIPS, long xecKeyId) throws OCKException;

    byte[] ECKEY_getPublicKeyBytes(boolean isFIPS, long ecKeyId) throws OCKException;

    byte[] XECKEY_getPublicKeyBytes(boolean isFIPS, long xecKeyId) throws OCKException;

    long ECKEY_createPKey(boolean isFIPS, long ecKeyId) throws OCKException;

    void ECKEY_delete(boolean isFIPS, long ecKeyId) throws OCKException;

    void XECKEY_delete(boolean isFIPS, long xecKeyId) throws OCKException;

    long XDHKeyAgreement_init(boolean isFIPS, long privId);

    void XDHKeyAgreement_setPeer(boolean isFIPS, long genCtx, long pubId);

    byte[] ECKEY_computeECDHSecret(boolean isFIPS, long pubEcKeyId, long privEcKeyId) throws OCKException;

    byte[] XECKEY_computeECDHSecret(boolean isFIPS, long genCtx, long pubEcKeyId, long privEcKeyId, int secrectBufferSize) throws OCKException;

    byte[] ECKEY_signDatawithECDSA(boolean isFIPS, byte[] digestBytes, int digestBytesLen, long ecPrivateKeyId) throws OCKException;

    boolean ECKEY_verifyDatawithECDSA(boolean isFIPS, byte[] digestBytes, int digestBytesLen, byte[] sigBytes, int sigBytesLen, long ecPublicKeyId) throws OCKException;

    // =========================================================================
    // HKDF functions
    // =========================================================================

    long HKDF_create(boolean isFIPS, String digestAlgo) throws OCKException;

    byte[] HKDF_extract(boolean isFIPS, long hkdfId, byte[] saltBytes, long saltLen, byte[] inKey, long inKeyLen) throws OCKException;

    byte[] HKDF_expand(boolean isFIPS, long hkdfId, byte[] prkBytes, long prkBytesLen, byte[] info, long infoLen, long okmLen) throws OCKException;

    byte[] HKDF_derive(boolean isFIPS, long hkdfId, byte[] saltBytes, long saltLen, byte[] inKey, long inKeyLen, byte[] info, long infoLen, long okmLen) throws OCKException;

    void HKDF_delete(boolean isFIPS, long hkdfId) throws OCKException;

    int HKDF_size(boolean isFIPS, long hkdfId) throws OCKException;

    // =========================================================================
    // Password based key derivation functions ( PBKDF )
    // =========================================================================

    byte[] PBKDF2_derive(boolean isFIPS, String hashAlgorithm, byte[] password, byte[] salt, int iterations, int keyLength) throws OCKException;

    // =========================================================================
    // ML-KEY key functions
    // =========================================================================

    long MLKEY_generate(boolean isFIPS, String cipherName) throws OCKException;

    long MLKEY_createPrivateKey(boolean isFIPS, String cipherName, byte[] privateKeyBytes) throws OCKException;

    long MLKEY_createPublicKey(boolean isFIPS, String cipherName, byte[] publicKeyBytes) throws OCKException;

    byte[] MLKEY_getPrivateKeyBytes(boolean isFIPS, long mlkeyId) throws OCKException;

    byte[] MLKEY_getPublicKeyBytes(boolean isFIPS, long mlkeyId) throws OCKException;

    void MLKEY_delete(boolean isFIPS, long mlkeyId);

    // =========================================================================
    // Key Encapsulation functions
    // =========================================================================

    void KEM_encapsulate(boolean isFIPS, long ockPKeyId, byte[] wrappedKey, byte[] randomKey) throws OCKException;

    byte[] KEM_decapsulate(boolean isFIPS, long ockPKeyId, byte[] wrappedKey) throws OCKException;

    // =========================================================================
    // PQC Signture functions - for use with ML-DSA and ML-SLH
    // =========================================================================

    byte[] PQC_SIGNATURE_sign(boolean isFIPS, long ockPKeyId, byte[] data) throws OCKException;

    boolean PQC_SIGNATURE_verify(boolean isFIPS, long ockPKeyId, byte[] sigBytes, byte[] data) throws OCKException;
}
