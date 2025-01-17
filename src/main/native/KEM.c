/*
 * Copyright IBM Corp. 2024
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
 * Method:    KEM_encapsulate
 * Signature: (JI)J
 */
JNIEXPORT void JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_KEM_1encapsulate
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jbyteArray publcKeyBytes, jbyteArray wrappedKey, jbyteArray randomKey)
{
  static const char * functionName = "NativeInterface.KEM_encapsulate";

  ICC_CTX *         ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_EVP_PKEY_CTX* evp_pk;
  ICC_EVP_PKEY*     pa = NULL;
  jlong             mlkeyId = 0;
  jint              wrappedkeylen = 0;
  jint              pubkeylen = 0;
  jint              genkeylen = 0;
  jboolean          isCopy = 0;
  unsigned char *   keyBytesNative = NULL;
  unsigned char*    wrappedKeyLocal = NULL;
  unsigned char*    genkeylocal = NULL;
  unsigned char *   wrappedKeyNative = NULL;
  unsigned char *   genKeyNative = NULL;

  if( debug ) {
    gslogFunctionEntry(functionName);
  }

  keyBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, publcKeyBytes, &isCopy));
  
  if( NULL == keyBytesNative ) {
    throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
  }

   pubkeylen = (*env)->GetArrayLength(env, publcKeyBytes);
  
  // Assume key is a PKCS1 key
  pa = ICC_d2i_PUBKEY(ockCtx, &pa, &keyBytesNative, (long)pubkeylen);

  evp_pk = ICC_EVP_PKEY_CTX_new_from_pkey(ockCtx, NULL, pa, NULL);
  if (!evp_pk) {
    throwOCKException(env, 0, "ICC_EVP_PKEY_CTX_new_from_pkey failed");
    ICC_EVP_PKEY_free(ockCtx, pa);
    return;
  }
  
  int rc = -1;

  rc = ICC_EVP_PKEY_encapsulate_init(ockCtx, NULL, NULL);
  if (rc != ICC_OSSL_SUCCESS) {
    throwOCKException(env, 0, "ICC_EVP_PKEY_encapsulate_init failed");
    ICC_EVP_PKEY_free(ockCtx, pa);
    return;
  }

  rc = ICC_EVP_PKEY_encapsulate(ockCtx, evp_pk, NULL, &wrappedkeylen, NULL, &genkeylen);
  if (rc != ICC_OSSL_SUCCESS) {
    throwOCKException(env, 0,"ICC_EVP_PKEY_encapsulate failed getting lenghts");
    ICC_EVP_PKEY_free(ockCtx, pa);
    return;
  }  

  wrappedKeyLocal = (unsigned char *)malloc(wrappedkeylen);
  genkeylocal = (unsigned char *)malloc(genkeylen);
  if (wrappedKeyLocal == NULL || genkeylocal == NULL) {
    if (wrappedKeyLocal != NULL){
      free(wrappedKeyLocal);
    }
    if (genkeylocal != NULL){
      free(wrappedKeyLocal);
      throwOCKException(env, 0, "malloc failed");
    } else {
      rc = ICC_EVP_PKEY_encapsulate(ockCtx, evp_pk, wrappedKeyLocal, &wrappedkeylen, genkeylocal, &genkeylen);
      if (rc != ICC_OSSL_SUCCESS) {
        throwOCKException(env, 0,"ICC_EVP_PKEY_encapsulate failed");
        ICC_EVP_PKEY_free(ockCtx, pa);
        return;
      }
      wrappedKey = (*env)->NewByteArray(env, wrappedkeylen);
      if( wrappedKey == NULL ) {
        throwOCKException(env, 0, "NewByteArray failed");
      } else {
        wrappedKeyNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, wrappedKeyLocal, &isCopy));
        if( wrappedKeyNative == NULL ) {
          throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical");
        } else {
          memcpy(wrappedKeyNative, wrappedKey, wrappedkeylen);

          randomKey = (*env)->NewByteArray(env, genkeylen);
          if( randomKey == NULL ) {
            throwOCKException(env, 0, "NewByteArray failed");
          } else {
            genKeyNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, genkeylocal, &isCopy));
            if( genKeyNative == NULL ) {
              throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical");
            } else {
              memcpy(genKeyNative, randomKey, genkeylen);
            }
          }
        }
      }
    }
  }  
  ICC_EVP_PKEY_free(ockCtx, pa);
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    MLKEY_decapsulate
 * Signature: (J[B)J
 */
JNIEXPORT void JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_KEM_1decapsulate
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jbyteArray privateKeyBytes, jbyteArray wrappedKey, jbyteArray randomKey)
{
  static const char * functionName = "NativeInterface.KEM_decapsulate";

  ICC_CTX *                ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_EVP_PKEY_CTX*        evp_pk;
  ICC_EVP_PKEY*            priv = NULL;
  ICC_PKCS8_PRIV_KEY_INFO* p8 = NULL;
  jboolean                 isCopy = 0;
  jint                     wrappedkeylen = 0;
  jint                     privkeylen = 0;
  jint                     genkeylen = 0;
  unsigned char *          keyBytesNative = NULL;
  unsigned char *          genkeylocal = NULL;
  unsigned char *          genKeyNative = NULL;

  keyBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, privateKeyBytes, &isCopy));
  
  if( NULL == keyBytesNative ) {
    throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
    return;
  }

   privkeylen = (*env)->GetArrayLength(env, privateKeyBytes);
  
  // Assume key is a PKCS8 key
	p8 = ICC_d2i_PKCS8_PRIV_KEY_INFO(ockCtx, NULL, &keyBytesNative, (long)privkeylen);

	if (!p8) {
    throwOCKException(env, 0, "ICC_d2i_PKCS8_PRIV_KEY_INFO failed");
	  return;
	}
	priv = ICC_EVP_PKCS82PKEY(ockCtx, p8);
	ICC_PKCS8_PRIV_KEY_INFO_free(ockCtx, p8);

  evp_pk = ICC_EVP_PKEY_CTX_new_from_pkey(ockCtx, NULL, priv, NULL);
  if (!evp_pk) {
    ICC_EVP_PKEY_free(ockCtx, priv);
    throwOCKException(env, 0, "ICC_EVP_PKEY_CTX_new_from_pkey failed");
    return;
  }

  int rc = -1;

  rc = ICC_EVP_PKEY_decapsulate_init(ockCtx, NULL, NULL);
  if (rc != ICC_OSSL_SUCCESS) {
    ICC_EVP_PKEY_free(ockCtx, priv);
    throwOCKException(env, 0, "ICC_EVP_PKEY_decapsulate_init failed");
    return;
  }

  wrappedkeylen = (*env)->GetArrayLength(env, wrappedKey);

  rc = ICC_EVP_PKEY_deccapsulate(ockCtx, evp_pk, NULL, &genkeylen, NULL, wrappedkeylen);
  if (rc != ICC_OSSL_SUCCESS) {
    ICC_EVP_PKEY_free(ockCtx, priv);
    throwOCKException(env, 0, "ICC_EVP_PKEY_deccapsulate to get lenghts failed");
    return;
  }  

  genkeylocal = (unsigned char *)malloc(genkeylen);
  if (genkeylocal == NULL) {
    ICC_EVP_PKEY_free(ockCtx, priv);
    throwOCKException(env, 0, "malloc failed");
  } else {
    rc = ICC_EVP_PKEY_decapsulate(ockCtx, evp_pk, genkeylocal, &genkeylen, wrappedKey, wrappedkeylen);
    if (rc != ICC_OSSL_SUCCESS) {
      ICC_EVP_PKEY_free(ockCtx, priv);
      free (genkeylocal);
      throwOCKException(env, 0, "ICC_EVP_PKEY_deccapsulate failed");
      return;
    }
    randomKey = (*env)->NewByteArray(env, genkeylen);
    if( randomKey == NULL ) {
      throwOCKException(env, 0, "NewByteArray failed");
    } else {
      genKeyNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, randomKey, &isCopy));
      if( genKeyNative == NULL ) {
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical");
      } else {
        memcpy(genKeyNative, randomKey, genkeylen);
      }
    }
  }
  ICC_EVP_PKEY_free(ockCtx, priv);
}
