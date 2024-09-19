/*
 * Copyright IBM Corp. 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

 package com.ibm.crypto.plus.provider.ock;

 import java.math.BigInteger;
 import java.util.Arrays;
 
 public final class OCKMLKEMKey implements AsymmetricKey {
 
     // The following is a special byte[] instance to indicate that the
     // private/public key bytes are available but not yet obtained.
     //
     static final byte[] unobtainedKeyBytes = new byte[0];
 
     private OCKContext ockContext;
     private long mlkemKeyId;
     private long pkeyId;
     private byte[] privateKeyBytes;
     private byte[] publicKeyBytes;
     private int keySize;
     private final static String badIdMsg = "ML-KEM Key Identifier is not valid";
     private final static String debPrefix = "OCKMLKEMKey";
 
     public static OCKMLKEMKey generateKeyPair(OCKContext ockContext, int numBits, BigInteger e)
             throws OCKException {
         //final String methodName = "generateKeyPair ";
         if (ockContext == null) {
             throw new IllegalArgumentException("context is null");
         }
 
         if (numBits < 0) {
             throw new IllegalArgumentException("key length is invalid");
         }
 
         long mlkemKeyId = NativeInterface.MLKEMKEY_generate(ockContext.getId(), numBits, e.longValue());
         //OCKDebug.Msg (debPrefix, methodName,  "numBits=" + numBits + " mlkemKeyId=" + mlkemKeyId);
         return new OCKMLKEMKey(ockContext, mlkemKeyId, unobtainedKeyBytes, unobtainedKeyBytes);
     }
 
     public static OCKMLKEMKey createPrivateKey(OCKContext ockContext, byte[] privateKeyBytes)
             throws OCKException {
         //final String methodName = "createPrivateKey ";
         if (ockContext == null) {
             throw new IllegalArgumentException("context is null");
         }
 
         if (privateKeyBytes == null) {
             throw new IllegalArgumentException("key bytes is null");
         }
 
         long mlkemKeyId = NativeInterface.MLKEMKEY_createPrivateKey(ockContext.getId(),
                 privateKeyBytes);
         //OCKDebug.Msg (debPrefix, methodName,  "mlkemKeyId :" + mlkemKeyId);
         return new OCKMLKEMKey(ockContext, mlkemKeyId, privateKeyBytes.clone(), null);
     }
 
     public static OCKMLKEMKey createPublicKey(OCKContext ockContext, byte[] publicKeyBytes)
             throws OCKException {
         //final String methodName = "createPublicKey ";
         if (ockContext == null) {
             throw new IllegalArgumentException("context is null");
         }
 
         if (publicKeyBytes == null) {
             throw new IllegalArgumentException("key bytes is null");
         }
 
         long MLKEMKeyId = NativeInterface.MLKEMKEY_createPublicKey(ockContext.getId(), publicKeyBytes);
         //OCKDebug.Msg (debPrefix, methodName,  "mlkemKeyId :" + mlkemKeyId);
         return new OCKMLKEMKey(ockContext, mlkemKeyId, null, publicKeyBytes.clone());
     }
 
     private OCKMLKEMKey(OCKContext ockContext, long mlkemKeyId, byte[] privateKeyBytes,
             byte[] publicKeyBytes) {
         this.ockContext = ockContext;
         this.mlkemKeyId = mlkemKeyId;
         this.pkeyId = 0;
         this.privateKeyBytes = privateKeyBytes;
         this.publicKeyBytes = publicKeyBytes;
         this.keySize = 0;
     }
 
     @Override
     public String getAlgorithm() {
         return "ML-KEM";
     }
 
     public long getMLKEMKeyId() {
         return this.mlkemKeyId;
     }
 
     @Override
     public long getPKeyId() throws OCKException {
         //final String methodName = "getPkeyId :";
         if (pkeyId == 0) {
             obtainPKeyId();
         }
         //OCKDebug.Msg(debPrefix, methodName,   this.pkeyId);
         return pkeyId;
     }
 
     // Not sure we need this.
     public int getKeySize() throws OCKException {
         //final String methodName = "getKeySize";
         if (keySize == 0) {
             obtainKeySize();
         }
         //OCKDebug.Msg (debPrefix, methodName, keySize);
         return keySize;
     }
 
     @Override
     public byte[] getPrivateKeyBytes() throws OCKException {
         //final String methodName = "getPrivateKeyBytes :";
         if (privateKeyBytes == unobtainedKeyBytes) {
             obtainPrivateKeyBytes();
         }
         //OCKDebug.Msg(debPrefix, methodName,  privateKeyBytes);
         return (privateKeyBytes == null) ? null : privateKeyBytes.clone();
     }
 
     @Override
     public byte[] getPublicKeyBytes() throws OCKException {
         //final String methodName = "getPrivateKeyBytes";
         if (publicKeyBytes == unobtainedKeyBytes) {
             obtainPublicKeyBytes();
         }
         //OCKDebug.Msg(debPrefix, methodName, publicKeyBytes);
         return (publicKeyBytes == null) ? null : publicKeyBytes.clone();
     }
 
     private synchronized void obtainPKeyId() throws OCKException {
         // Leave this duplicate check in here. If two threads are both trying
         // to getPKeyId at the same time, we only want to call the native
         // code one time.
         //
         if (pkeyId == 0) {
             if (!validId(mlkemKeyId)) {
                 throw new OCKException(badIdMsg);
             }
             this.pkeyId = NativeInterface.MLKEMKEY_createPKey(ockContext.getId(), mlkemeyId);
         }
     }
 
     private synchronized void obtainPrivateKeyBytes() throws OCKException {
         // Leave this duplicate check in here. If two threads are both trying
         // to getPrivateKeyBytes at the same time, we only want to call the
         // native code one time.
         //
         if (privateKeyBytes == unobtainedKeyBytes) {
             if (!validId(mlkemKeyId)) {
                 throw new OCKException(badIdMsg);
             }
             this.privateKeyBytes = NativeInterface.MLKEMEY_getPrivateKeyBytes(ockContext.getId(),
                     mlkemKeyId);
         }
     }
 
     private synchronized void obtainPublicKeyBytes() throws OCKException {
         // Leave this duplicate check in here. If two threads are both trying
         // to getPublicKeyBytes at the same time, we only want to call the
         // native code one time.
         //
         if (publicKeyBytes == unobtainedKeyBytes) {
             if (!validId(mlkemKeyId)) {
                 throw new OCKException(badIdMsg);
             }
             this.publicKeyBytes = NativeInterface.MLKEMKEY_getPublicKeyBytes(ockContext.getId(),
                     mlkemKeyId);
         }
     }
 
     //Not sure we need this since size is in the Alg.
     private synchronized void obtainKeySize() throws OCKException {
         // Leave this duplicate check in here. If two threads are both trying
         // to obtainKeySize at the same time, we only want to call the
         // native code one time.
         //
         if (this.keySize == 0) {
             if (!validId(mlkemKeyId)) {
                 throw new OCKException(badIdMsg);
             }
             this.keySize = NativeInterface.MLKEMKEY_size(ockContext.getId(), mlkemKeyId);
         }
     }
 
     @Override
     protected synchronized void finalize() throws Throwable {
         //final String methodName = "finalize ";
         //OCKDebug.Msg(debPrefix, methodName, "mlkemKeyId=" + mlkemKeyId + " pkeyId=" + pkeyId);
         try {
             if ((privateKeyBytes != null) && (privateKeyBytes != unobtainedKeyBytes)) {
                 Arrays.fill(privateKeyBytes, (byte) 0x00);
             }
 
             if (mlkemKeyId != 0) {
                 NativeInterface.mlkemKEY_delete(ockContext.getId(), mlkemKeyId);
                 mlkemKeyId = 0;
             }
 
             if (pkeyId != 0) {
                 NativeInterface.PKEY_delete(ockContext.getId(), pkeyId);
                 pkeyId = 0;
             }
         } finally {
             super.finalize();
         }
     }
 
     /* At some point we may enhance this function to do other validations */
     protected static boolean validId(long id) {
         //final String methodName = "validId";
         //OCKDebug.Msg(debPrefix, methodName, id);
         return (id != 0L);
     }
 
 }
 