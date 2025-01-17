/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <jcc_a.h>
#include <icc.h>

#include "com_ibm_crypto_plus_provider_ock_NativeInterface.h"
#include "Utils.h"
#include <stdint.h>

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    MLKEY_generate
 * Signature: (JI)J
 */
JNIEXPORT jlong JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_MLKEY_1generate
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jstring cipherName)
{
  static const char * functionName = "NativeInterface.MLKEY_generate";

  ICC_CTX *         ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_EVP_PKEY_CTX* evp_sp; 
  jlong             mlkeyId = 0;

  if( debug ) {
    gslogFunctionEntry(functionName);
  }

  if (cipherName == NULL) {
    return 0;
  }

  evp_sp = ICC_EVP_PKEY_CTX_new_from_name(ockCtx, cipherName, NULL);
  if (!evp_sp) {
    const int nid = ICC_OBJ_txt2nid(ockCtx, cipherName);
    if (!nid) {
      throwOCKException(env, 0, "Key generation failed - ICC_OBJ_txt2nid");
      return;
    }

    evp_sp = ICC_EVP_PKEY_CTX_new_id(ockCtx, nid, NULL);
    if (!evp_sp) {
      throwOCKException(env, 0, "Key generation failed - ICC_EVP_PKEY_CTX_new_id");
      return ;
    }

    int rv = ICC_OSSL_SUCCESS;
    rv = ICC_EVP_PKEY_keygen_init(ockCtx, evp_sp);
    if (rv != ICC_OSSL_SUCCESS) {
      if (evp_sp) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_sp);
      }
      throwOCKException(env, 0, "Key generation failed");
      return 0;
    }

    ICC_EVP_PKEY* pa = NULL;

    rv = ICC_EVP_PKEY_keygen(ockCtx, evp_sp, &pa);
    if (rv != ICC_OSSL_SUCCESS) {
      if (evp_sp) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_sp);
      }
      if (pa) {
        ICC_EVP_PKEY_free(ockCtx, pa);
      }
      throwOCKException(env, 0, "Key generation failed");
      return 0;
    }

    mlkeyId = (jlong)((intptr_t)pa);
  }  

  if (evp_sp) {
    ICC_EVP_PKEY_CTX_free(ockCtx, evp_sp);
  }

  return mlkeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    MLKEY_createPrivateKey
 * Returns:   pointer to PKCS 8 Private Key
 * Signature: (J[B)J
 */
JNIEXPORT jlong JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_MLKEY_1createPrivateKey
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jstring cipherName, jbyteArray privateKeyBytes)
{
  static const char * functionName = "NativeInterface.MLKEY_createPrivateKey";

  ICC_CTX *                 ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_EVP_PKEY *            ockPKey = NULL;
  ICC_PKCS8_PRIV_KEY_INFO * p8 = NULL;
  unsigned char *           keyBytesNative = NULL;
  jboolean                  isCopy = 0;
  jlong                     mlkeyId = 0;
  unsigned char *           pBytes = NULL;
  long                      size = 0;

  if (privateKeyBytes == NULL) {
    throwOCKException(env, 0, "The ML Key Private Key bytes are incorrect.");
  	return mlkeyId;
  }

  keyBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, privateKeyBytes, &isCopy));
  if( NULL == keyBytesNative ) {
    throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
  } else {
    pBytes = (unsigned char *)keyBytesNative;
    size = (*env)->GetArrayLength(env, privateKeyBytes);
    p8 = ICC_d2i_PKCS8_PRIV_KEY_INFO(ockCtx, NULL, &pBytes, size); 
    if( NULL == ockPKey ) {
      ockCheckStatus(ockCtx);
      throwOCKException(env, 0, "ICC_EVP_PKEY_new failed");
    } else {
      ockPKey = ICC_EVP_PKCS82PKEY(ockCtx, p8);
      if( ockPKey == NULL ) {
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_EVP_PKCS82PKEY failed");
      } else {

        mlkeyId = (jlong)((intptr_t)ockPKey);

      }
    }
  }

  if( keyBytesNative != NULL ) {
    (*env)->ReleasePrimitiveArrayCritical(env, privateKeyBytes, keyBytesNative, 0);
  }
  if ( p8 != NULL ) {
    ICC_PKCS8_PRIV_KEY_INFO_free(ockCtx, p8);
  }

  return mlkeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    MLKEY_createPublicKey
 * Return:    PKCS 1 key
 * Signature: (J[B)J
 */
JNIEXPORT jlong JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_MLKEY_1createPublicKey
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jbyteArray publicKeyBytes)
{
  static const char * functionName = "NativeInterface.MLKEY_createPublicKey";

  ICC_CTX *       ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_EVP_PKEY *  ockPKey = NULL;
  unsigned char * keyBytesNative = NULL;
  jboolean        isCopy = 0;
  jlong           mlkeyId = 0;
  unsigned char * pBytes = NULL;
  long            size = 0;

  if (publicKeyBytes == NULL) {
    throwOCKException(env, 0, "The MLKEY Key Public bytes are incorrect.");
  	return mlkeyId;
  }
  keyBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, publicKeyBytes, &isCopy));
  if( NULL == keyBytesNative ) {
    throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
  } else {

    pBytes = (unsigned char *)keyBytesNative;
    size = (*env)->GetArrayLength(env, publicKeyBytes);

    ockPKey = ICC_d2i_PUBKEY(ockCtx, &ockPKey, &pBytes, size);
    if( ockPKey == NULL ) {
      ockCheckStatus(ockCtx);
      throwOCKException(env, 0, "ICC_d2i_PublicKey failed");
    } else {
      mlkeyId = (jlong)((intptr_t)ockPKey);
    }
  }

  if( keyBytesNative != NULL ) {
    (*env)->ReleasePrimitiveArrayCritical(env, publicKeyBytes, keyBytesNative, 0);
  }

  return mlkeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    MLKEY_getPrivateKeyBytes
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_MLKEY_1getPrivateKeyBytes
  (JNIEnv * env, jclass thisObj, jlong ockContextId, jlong mlkeyId)
{
  static const char * functionName = "NativeInterface.MLKEY_getPrivateKeyBytes";

  ICC_CTX *       ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_EVP_PKEY*   ockKey = (ICC_EVP_PKEY*)((intptr_t) mlkeyId);
  jbyteArray      keyBytes = NULL;
  unsigned char * keyBytesNative = NULL;
  jboolean        isCopy = 0;
  int             size;
  jbyteArray      retKeyBytes = NULL;

  if (NULL == ockKey) {
    throwOCKException(env, 0, "The Key identifier is incorrect.");
	  return retKeyBytes;
  }

  size = ICC_i2d_PrivateKey(ockCtx, ockKey, NULL);
  if( size <= 0 ) {
    ockCheckStatus(ockCtx);
    throwOCKException(env, 0, "ICC_i2d_PrivateKey failed");
  } else {
    keyBytes = (*env)->NewByteArray(env, size);
    if( keyBytes == NULL ) {
      throwOCKException(env, 0, "NewByteArray failed");
    } else {
      keyBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, keyBytes, &isCopy));
      if( keyBytesNative == NULL ) {
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical");
      } else {
        unsigned char * pBytes = (unsigned char *)keyBytesNative;

        size = ICC_i2d_PrivateKey(ockCtx, ockKey, &pBytes);
        if( size <= 0 ) {
          ockCheckStatus(ockCtx);
          throwOCKException(env, 0, "ICC_i2d_PrivateKey failed");
        } else {
          retKeyBytes = keyBytes;
        }
      }
    }
  }

  if( keyBytesNative != NULL ) {
    (*env)->ReleasePrimitiveArrayCritical(env, keyBytes, keyBytesNative, 0);
  }

  if( (keyBytes != NULL) && (retKeyBytes == NULL) ) {
    (*env)->DeleteLocalRef(env, keyBytes);
  }

  return retKeyBytes;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    MLKEY_getPublicKeyBytes
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_MLKEY_1getPublicKeyBytes
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jlong mlkeyId )
{
  static const char * functionName = "NativeInterface.MLKEY_getPublicKeyBytes";

  ICC_CTX *       ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_EVP_PKEY*   ockKey = (ICC_EVP_PKEY*)((intptr_t) mlkeyId);
  jbyteArray      keyBytes = NULL;
  unsigned char * keyBytesNative = NULL;
  jboolean        isCopy = 0;
  long            size = 0;
  jbyteArray      retKeyBytes = NULL;

  if (ockKey == NULL) {
  	return retKeyBytes;
  }

  size = ICC_i2d_PublicKey(ockCtx, ockKey, NULL);
  if( size <= 0 ) {
    ockCheckStatus(ockCtx);
    throwOCKException(env, 0, "ICC_i2d_PublicKey failed");
  } else {
    keyBytes = (*env)->NewByteArray(env, size);
    if( keyBytes == NULL ) {
      throwOCKException(env, 0, "NewByteArray failed");
    } else {
      keyBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, keyBytes, &isCopy));
      if( keyBytesNative == NULL ) {
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical");
      } else {
        unsigned char * pBytes = (unsigned char *)keyBytesNative;

        size = ICC_i2d_PublicKey(ockCtx, ockKey, &pBytes);
        if( size <= 0 ) {
          ockCheckStatus(ockCtx);
          throwOCKException(env, 0, "ICC_i2d_PublicKey failed");
        } else {
          retKeyBytes = keyBytes;
        }
      }
    }
  }

  if( keyBytesNative != NULL ) {
    (*env)->ReleasePrimitiveArrayCritical(env, keyBytes, keyBytesNative, 0);
  }

  if( (keyBytes != NULL) && (retKeyBytes == NULL) ) {
    (*env)->DeleteLocalRef(env, keyBytes);
  }

  return keyBytes;
}

//============================================================================
/*  
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    MLKEY_createPKey
 * Signature: (JJ)J
 */
JNIEXPORT jlong JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_MLKEY_1createPKey
  (JNIEnv * env, jclass thisObj, jlong ockContextId, jlong mlkeyId)
{
  static const char * functionName = "NativeInterface.MLKEY_createPKey";

  ICC_CTX *      ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_EVP_PKEY*  ockKeys = (ICC_EVP_PKEY *)((intptr_t) mlkeyId);
  ICC_EVP_PKEY * ockPKey = NULL;
  jlong          pkeyId = 0;

  if (ockKeys == NULL) {
    throwOCKException(env, 0, "The Key identifier is incorrect.");
  	return pkeyId;
  }

  ockPKey = ICC_EVP_PKEY_new(ockCtx);
  if( ockPKey == NULL ) {
    ockCheckStatus(ockCtx);
    throwOCKException(env, 0, "ICC_EVP_PKEY_new failed");
  } else {
    int rc = ICC_EVP_PKEY_set1_MLKEY(ockCtx, ockPKey, ockKeys);
    if( rc != ICC_OSSL_SUCCESS ) {
      ockCheckStatus(ockCtx);
      throwOCKException(env, 0, "ICC_EVP_PKEY_set1_MLKEY failed");
    } else {
      pkeyId = (jlong)((intptr_t)ockPKey);
    }
  }

  if( (ockPKey != NULL) && (pkeyId == 0) ) {
    ICC_EVP_PKEY_free(ockCtx, ockPKey);
    ockPKey = NULL;
  }

  return pkeyId;
}


//============================================================================
/* NOTE: NOt SURE WE NEED THIS.
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    MLKEY_delete
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_MLKEY_1delete
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jlong mlkeyId)
{
  static const char * functionName = "NativeInterface.MLKEY_delete";

  ICC_CTX *      ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_EVP_PKEY * ockKey = (ICC_EVP_PKEY *)((intptr_t) mlkeyId);

  if (ockKey != NULL) {
	  ICC_EVP_PKEY_free(ockCtx, ockKey);
	  ockKey = NULL;
  }

}
