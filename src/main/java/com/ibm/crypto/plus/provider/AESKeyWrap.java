/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.Padding;
import com.ibm.crypto.plus.provider.ock.SymmetricCipher;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

public final class AESKeyWrap extends CipherSpi {

    private OpenJCEPlusProvider provider = null;
    private boolean wrappering = true;
    private boolean initialized = false;

    public AESKeyWrap(OpenJCEPlusProvider provider) {
        if (!OpenJCEPlusProvider.verifySelfIntegrity(this)) {
            throw new SecurityException("Integrity check failed for: " + provider.getName());
        }
        this.provider = provider;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        throw new IllegalStateException("Cipher has not been initialized");
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        throw new IllegalStateException("Cipher has not been initialized");
    }

    @Override
    protected int engineGetBlockSize() {
        return AESConstants.AES_BLOCK_SIZE;
    }

    @Override
    protected byte[] engineGetIV() {
        return null;
    }

    @Override
    protected int engineGetKeySize(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key missing");
        }

        byte[] encoded = key.getEncoded();
        if (!AESUtils.isKeySizeValid(encoded.length)) {
            throw new InvalidKeyException("Invalid AES key length: " + encoded.length + " bytes");
        }
        return encoded.length << 3;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        int result = 0;
        if (!wrappering) {
            result = inputLen - 16;
        } else {
            result = Math.addExact(inputLen, 16);
        }
        return (result < 0? 0:result);
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        AlgorithmParameters params = null;

        return params;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {

        if (opmode == Cipher.UNWRAP_MODE) {
            wrappering = false;
        } else if (opmode == Cipher.WRAP_MODE) {
            wrappering = true;
        } else {
            throw new UnsupportedOperationException("This cipher can " +
                "only be used for key wrapping and unwrapping");
        }

        internalInit(opmode, key);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params,
            SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("This cipher " +
                "does not accept any parameters");
        }
        engineInit(opmode, key, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("This cipher " +
                "does not accept any parameters");
        }
        engineInit(opmode, key, random);
    }

    private void internalInit(int opmode, Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key missing");
        }

        if (!(key.getAlgorithm().equalsIgnoreCase("AES"))) {
            throw new InvalidKeyException("Wrong algorithm: AES required");
        }

        byte[] rawKey = key.getEncoded();
        if (rawKey == null) {
            throw new InvalidKeyException("Key bytes are missing");
        }

        if (!AESUtils.isKeySizeValid(rawKey.length)) {
            throw new InvalidKeyException("Invalid AES key length: " + rawKey.length + " bytes");
        }

    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
       if (!mode.equalsIgnoreCase("ECB")) {
            throw new NoSuchAlgorithmException("Only ECB mode is supported.");
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (!padding.equalsIgnoreCase("NoPadding")) {
            throw new NoSuchPaddingException(padding + " can not be used.");
        }
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        throw new IllegalStateException("Cipher has not been initialized");
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset) throws ShortBufferException {
        throw new IllegalStateException("Cipher has not been initialized");
    }

    // see JCE spec
    protected byte[] engineWrap(Key key) throws InvalidKeyException, IllegalBlockSizeException {
        checkCipherInitialized();

        byte[] encoded = key.getEncoded();
        if ((encoded == null) || (encoded.length == 0)) {
            throw new InvalidKeyException("Could not obtain encoded key");
        }

        try {
            return engineDoFinal(encoded, 0, encoded.length);
        } catch (BadPaddingException e) {
            // should not occur
            throw new InvalidKeyException("Wrapping failed", e);
        }
    }

    // see JCE spec
    protected Key engineUnwrap(byte[] wrappedKey, String algorithm, int type)
            throws InvalidKeyException, NoSuchAlgorithmException {
        checkCipherInitialized();

        try {
            byte[] encoded = engineDoFinal(wrappedKey, 0, wrappedKey.length);
            return ConstructKeys.constructKey(provider, encoded, algorithm, type);
        } catch (BadPaddingException e) {
            // should not occur
            throw new InvalidKeyException("Unwrapping failed", e);
        } catch (IllegalBlockSizeException e) {
            // should not occur, handled with length check above
            throw new InvalidKeyException("Unwrapping failed", e);
        }
    }

    private void checkCipherInitialized() throws IllegalStateException {
        if (!this.initialized) {
            throw new IllegalStateException("Cipher has not been initialized");
        }
    }
}
