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
JNIEXPORT jlong JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_KEM_1encapsulate
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



  if( debug ) {
    gslogFunctionExit(functionName);
  }
// Add code to remove PKEY context created above.

  return mlkeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    MLKEY_decapsulate
 * Signature: (J[B)J
 */
JNIEXPORT jlong JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_MLKEY_1createPrivateKey
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jstring cipherName, jlong privateKey)
{
  static const char * functionName = "NativeInterface.KEM_decapsulate";

  ICC_CTX *       ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_MLKEY *     ockMLKEY = NULL;
  ICC_EVP_PKEY *  ockPKey = NULL;
  unsigned char * keyBytesNative = NULL;
  jboolean        isCopy = 0;
  jlong           mlkeyId = 0;
  unsigned char * pBytes = NULL;
  jint            size = 0;

  if( debug ) {
    gslogFunctionEntry(functionName);
  }

ICC_EVP_PKEY_CTX* skc = p_skc->ctx; // private key

   int rc;

   rc = ICC_EVP_PKEY_decapsulate_init(c, NULL, NULL);
   if (rc != ICC_OSSL_SUCCESS) {
      return 1;
   }

   /* peer's public key is just the ss encrypted (by peer) with our public key */
   size_t wrappedkeylen = 0;
   wrappedkeylen = p_pks->len;
   unsigned char* wrappedkey = p_pks->data;

   size_t genkeylen = 0;

   rc = ICC_EVP_PKEY_decapsulate(c, skc, NULL, &genkeylen, NULL, wrappedkeylen);
   if (rc != ICC_OSSL_SUCCESS) {
      return 2;
   }

   kbuf gk;
   gk.len = genkeylen;
   gk.data = malloc(genkeylen);
   unsigned char* genkey = gk.data;
   //unsigned char* unwrapped, size_t* unwrappedlen, const unsigned char* wrapped, size_t wrappedlen
   rc = ICC_EVP_PKEY_decapsulate(c, skc, genkey, &genkeylen, wrappedkey, wrappedkeylen);
   if (rc != ICC_OSSL_SUCCESS) {
      return 3;
   }

   *ss = gk;

   return 0;


  if (privateKeyBytes == NULL) {
    throwOCKException(env, 0, "The ML Key Private Key bytes are incorrect.");
	if( debug ) {
	  gslogFunctionExit(functionName);
	}
	return mlkeyId;
  }
  keyBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, privateKeyBytes, &isCopy));
  if( NULL == keyBytesNative ) {
#ifdef DEBUG_MLKEY_DETAIL
    if ( debug ) {
       gslogMessage ("DETAIL_MLKEY  FAILURE keyBytesNative");
    }
#endif
    throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
  } else {
    if ( debug ) {
      gslogMessage ("DETAIL_MLKEY KeyBytesNative allocated");
    }
//  unsigned char * pBytes = (unsigned char *)keyBytesNative;
    pBytes = (unsigned char *)keyBytesNative;
//  jint size = (*env)->GetArrayLength(env, privateKeyBytes);
    size = (*env)->GetArrayLength(env, privateKeyBytes);
#ifdef DEBUG_MLKEY_DATA
    if ( debug ) {
      gslogMessagePrefix ("DATA_MLKEY Private KeyBytes : ");
      gslogMessageHex ((char *) pBytes, 0, (int) size, 0, 0, NULL);
    }
#endif

    ockPKey = ICC_EVP_PKEY_new(ockCtx);
    if( NULL == ockPKey ) {
      ockCheckStatus(ockCtx);
#ifdef DEBUG_MLKEY_DETAIL
    if ( debug ) {
       gslogMessage ("DETAIL_MLKEY  FAILURE ICC_EVP_PKEY_new ");
    }
#endif
      throwOCKException(env, 0, "ICC_EVP_PKEY_new failed");
    } else {
      ICC_EVP_PKEY * ret = ICC_d2i_PrivateKey(ockCtx, cipherName, &ockPKey, &pBytes, (long)size);
#ifdef DEBUG_MLKEY_DETAIL
    if ( debug ) {
      gslogMessage ("DETAIL_MLKEY pointer to ICC_EVP_PKEY %x", ret);
    }
#endif
      if( ret == NULL ) {
        ockCheckStatus(ockCtx);
#ifdef DEBUG_MLKEY_DETAIL
        if ( debug ) {
          gslogMessage ("DETAIL_MLKEY  FAILURE ICC_d2i_PrivateKey");
        }
#endif
        throwOCKException(env, 0, "ICC_d2i_PrivateKey failed");
      } else {
        ockKey = ICC_EVP_PKEY_new_from_pkey(ockCtx, ockPKey, NULL);
        if( ockKey == NULL ) {
#ifdef DEBUG_MLKEY_DETAIL
          if ( debug ) {
            gslogMessage ("DETAIL_MLKEY  FAILURE ICC_EVP_PKEY_new_from_pkey");
          }
#endif
          ockCheckStatus(ockCtx);
          throwOCKException(env, 0, "ICC_EVP_PKEY_new_from_pkey failed");
        } else {
          mlkeyId = (jlong)((intptr_t)ockKey);
#ifdef DEBUG_MLKEY_DETAIL
          if ( debug ) {
            gslogMessage ("DETAIL_MLKEY  mlkeyId %lx", mlkeyId);
          }
#endif
        }
      }
    }
  }

  if( keyBytesNative != NULL ) {
    (*env)->ReleasePrimitiveArrayCritical(env, privateKeyBytes, keyBytesNative, 0);
  }

  if( ockPKey != NULL ) {
    ICC_EVP_PKEY_free(ockCtx, ockPKey);
    ockPKey = NULL;
  }

  if( debug ) {
    gslogFunctionExit(functionName);
  }

  return mlkeyId;
}
