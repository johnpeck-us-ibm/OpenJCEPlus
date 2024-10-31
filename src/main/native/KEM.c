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
  unsigned char *   keyBytesNative = NULL;
  unsigned char*    wrappedkeylocal = null;
  unsigned char*    genkeylocal = null;
  unsigned char *   wrappedkeyNative = NULL;
  unsigned char *   genkeyNative = NULL;

  if( debug ) {
    gslogFunctionEntry(functionName);
  }

    keyBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, publcKeyBytes, &isCopy));
  
  if( NULL == keyBytesNative ) {
#ifdef DEBUG_KEM_DETAIL
    if ( debug ) {
       gslogMessage ("DETAIL_KEM  FAILURE keyBytesNative");
    }
#endif
    throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
  } else {
    if ( debug ) {
      gslogMessage ("DETAIL_RSA KeyBytesNative allocated");
    }
  }

   pubkeylen = (*env)->GetArrayLength(env, publcKeyBytes);
  
  // Assume key is a PKCS1 key
   pa = ICC_d2i_PUBKEY(ockCtx, &pa, &nativeKeyBytes, (long)pubkeylen);

   evp_pk = ICC_EVP_PKEY_CTX_new_from_pkey(ockCtx, NULL, pa, NULL);
   if (!evp_pk) {
      return 2;
      //throw ICC_err(ICC_err::err::failed, "KyberEVP::ICC_EVP_PKEY_CTX_new_from_pkey", -1);
   }
   //evp_pk = p_pkc.get();

   int rc = -1;

   rc = ICC_EVP_PKEY_encapsulate_init(ockCtx, NULL, NULL);
   if (rc != ICC_OSSL_SUCCESS) {
      return 3;
      //throw ICC_err(ICC_err::err::failed, "KyberEVP::ICC_EVP_PKEY_encapsulate_init", rc);
   }



   rc = ICC_EVP_PKEY_encapsulate(ockCtx, evp_pk, NULL, &wrappedkeylen, NULL, &genkeylen);
   if (rc != ICC_OSSL_SUCCESS) {
      return 4;
      //throw ICC_err(ICC_err::err::failed, "KyberEVP::ICC_EVP_PKEY_encapsula
      mlkeyId = (jlong)((intptr_t)pa);
  }  

    wrappedkeylocal = (unsigned char *)malloc(wrappedkeylen);
    genkeylocal = (unsigned char *)malloc(genkeylen);
    if (wrappedkeylocal == NULL || genkeylocal == NULL) {
      if (wrappedkeylocal != NULL){
        free(wrappedkeylocal);
      }
      if (genkeylocal != NULL){
        free(wrappedkeylocal);
      }
      throwOCKException(env, 0, "malloc failed");
    } else {
        rc = ICC_EVP_PKEY_encapsulate(ockCtx, evp_pk, wrappedkeylocal, &wrappedkeylen, genkeylocal, &genkeylen);
        if (rc != ICC_OSSL_SUCCESS) {
           return 5;
        }
        wrappedKey = (*env)->NewByteArray(env, wrappedkeylen);
        if( sigBytes == NULL ) {
          throwOCKException(env, 0, "NewByteArray failed");
        } else {
          wrappedKeyNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, wrappedKey, &isCopy));
          if( wrappedKeyNative == NULL ) {
            throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical");
          } else {
            memcpy(wrappedKeyNative, wrappedKeyLocal, wrappedkeylen);
          }
        }
        randomKey = (*env)->NewByteArray(env, genkeylen);
        if( sigBytes == NULL ) {
          throwOCKException(env, 0, "NewByteArray failed");
        } else {
          genKeyNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, randomKey, &isCopy));
          if( wrappedKeyNative == NULL ) {
            throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical");
          } else {
            memcpy(wrappedKeyNative, genkeyLocal, genkeylen);
          }
        }
      }
    }
  ICC_EVP_PKEY_free(ctx, pa);

  if( debug ) {
    gslogFunctionExit(functionName);
  }
// Add code to remove PKEY context created above.

  return;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    MLKEY_decapsulate
 * Signature: (J[B)J
 */
JNIEXPORT jlong JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_KEM_1decapsulate
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jstring cipherName, jbyteArray privateKeyBytes, jbyteArray wrappedKey, jbyteArray randomKey)
{
  static const char * functionName = "NativeInterface.KEM_decapsulate";

  ICC_CTX *                ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_EVP_PKEY_CTX*        evp_pk;
  ICC_EVP_PKEY*            priv = NULL;
  ICC_PKCS8_PRIV_KEY_INFO* p8 = NULL;
  jint                     wrappedkeylen = 0;
  jint                     privkeylen = 0;
  jint                     genkeylen = 0;
  unsigned char *          keyBytesNative = NULL;
  unsigned char *          genkeylocal = null;
  unsigned char *          genkeyNative = NULL;

  if( debug ) {
    gslogFunctionEntry(functionName);
  }

    keyBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, privateKeyBytes, &isCopy));
  
  if( NULL == keyBytesNative ) {
#ifdef DEBUG_KEM_DETAIL
    if ( debug ) {
       gslogMessage ("DETAIL_KEM  FAILURE keyBytesNative");
    }
#endif
    throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
  } else {
    if ( debug ) {
      gslogMessage ("DETAIL_RSA KeyBytesNative allocated");
    }
  }

   privkeylen = (*env)->GetArrayLength(env, privateKeyBytes);
  
  // Assume key is a PKCS8 key
	p8 = ICC_d2i_PKCS8_PRIV_KEY_INFO(ctx, NULL, &keyBytesNative, (long)privkeylen);

	if (!p8) {
	  return 11;
	}
	priv = ICC_EVP_PKCS82PKEY(ctx, p8);
	ICC_PKCS8_PRIV_KEY_INFO_free(ctx, p8);

  evp_pk = ICC_EVP_PKEY_CTX_new_from_pkey(ockCtx, NULL, priv, NULL);
  if (!evp_pk) {
     return 2;
     //throw ICC_err(ICC_err::err::failed, "KyberEVP::ICC_EVP_PKEY_CTX_new_from_pkey", -1);
  }

  int rc = -1;

  rc = ICC_EVP_PKEY_decapsulate_init(ockCtx, NULL, NULL);
  if (rc != ICC_OSSL_SUCCESS) {
     return 3;
     //throw ICC_err(ICC_err::err::failed, "KyberEVP::ICC_EVP_PKEY_encapsulate_init", rc);
  }

  wrappedkeylen = (*env)->GetArrayLength(env, wrappedKey);

  rc = ICC_EVP_PKEY_deccapsulate(ockCtx, evp_pk, NULL, &genkeylen, NULL, wrappedkeylen);
  if (rc != ICC_OSSL_SUCCESS) {
      return 4;
      //throw ICC_err(ICC_err::err::failed, "KyberEVP::ICC_EVP_PKEY_decapsulate", -1;
      mlkeyId = (jlong)((intptr_t)pa);
  }  

    genkeylocal = (unsigned char *)malloc(genkeylen);
    if (genkeylocal == NULL) {
      throwOCKException(env, 0, "malloc failed");
    } else {
        rc = ICC_EVP_PKEY_decapsulate(ockCtx, evp_pk, genkeylocal, &genkeylen, wrappedKey, wrappedkeylen);
        if (rc != ICC_OSSL_SUCCESS) {
           return 5;
        }
        randomKey = (*env)->NewByteArray(env, genkeylen);
        if( sigBytes == NULL ) {
          throwOCKException(env, 0, "NewByteArray failed");
        } else {
          genKeyNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, randomKey, &isCopy));
          if( wrappedKeyNative == NULL ) {
            throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical");
          } else {
            memcpy(wrappedKeyNative, genkeyLocal, genkeylen);
          }
        }
      }
    }
  ICC_EVP_PKEY_free(ctx, priv);

  if( debug ) {
    gslogFunctionExit(functionName);
  }
// Add code to remove PKEY context created above?

  return;
}
