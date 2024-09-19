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
 * Method:    MLKEMKEY_generate
 * Signature: (JI)J
 */
JNIEXPORT jlong JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_MLKEMKEY_1generate
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jstring cipherName, jlong e)
{
  static const char * functionName = "NativeInterface.MLKEMKEY_generate";

  ICC_CTX *         ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_EVP_PKEY_CTX* evp_sp; 
  jlong             mlkemkeyId = 0;

  if( debug ) {
    gslogFunctionEntry(functionName);
  }

  if (ciphername == null) {
    return 0;
  }

 evp_sp = ICC_EVP_PKEY_CTX_new_from_name(ctx, cipherName, NULL);
      if (!evp_sp) {
         const int nid = ICC_OBJ_txt2nid(ctx, cipherName);
         if (!nid) {
            return 1;
            //throw ICC_err(ICC_err::err::not_supported, "ICC_OBJ_txt2nid:" + getMode(), getICC());
         }
         evp_sp = ICC_EVP_PKEY_CTX_new_id(ctx, nid, NULL);
         if (!evp_sp) {
            return 2;
            // Usually caused by non-FIPS ICC not available. FIPS wont do named curves
            //throw ICC_err(ICC_err::err::not_supported, "ICC_EVP_PKEY_CTX_new_id", getICC());
         }
      }
      int rv = ICC_OSSL_SUCCESS;
      rv = ICC_EVP_PKEY_keygen_init(ctx, evp_sp);
      if (rv != ICC_OSSL_SUCCESS) {
         if (evp_sp) {
            ICC_EVP_PKEY_CTX_free(ctx, evp_sp);
         }
         return 3;
         //throw ICC_err(ICC_err::err::not_supported, getMode() + ":Keygen Init", getICC());
      }

      ICC_EVP_PKEY* pa = NULL;

      rv = ICC_EVP_PKEY_keygen(ctx, evp_sp, &pa);
      if (rv != ICC_OSSL_SUCCESS) {
         if (evp_sp) {
            ICC_EVP_PKEY_CTX_free(ctx, evp_sp);
         }
         if (pa) {
            ICC_EVP_PKEY_free(ctx, pa);
         }
         return 4;
         //throw ICC_err(ICC_err::err::not_supported, getMode() + ":Keygen", getICC());
      }
      
      mlkemkeyId = (jlong)((intptr_t)pa);

      size_t bits = 0;
      bits = ICC_EVP_PKEY_size(ctx, pa);

      unsigned char* pp = NULL;
      int pub_len = ICC_i2d_PublicKey(ctx, pa, NULL);
      if (pub_len <= 0) {
         return 5;
         //throw ICC_err(ICC_err::err::invalid, "ICC_i2d_PublicKey", getICC());
      }
      pkbuf pubDer;
      pubDer.len = pub_len;
      pp = pubDer.data = malloc(pub_len);
      rv = ICC_i2d_PublicKey(ctx, pa, &pp);
      if (rv <= 0) {
         return 6;
         //throw ICC_err(ICC_err::err::invalid, "ICC_i2d_PublicKey", getICC());
      }

      ICC_EVP_PKEY_free(ctx, pa);

      *p_pkc = pubDer;

      p_skc->ctx = evp_sp;
      rc = 0;
   }
   if (rc) {
      return 7;
      //throw ICC_err(ICC_err::err::failed, "KyberEVP::gen", rc);
   }

   return 0;


  if( debug ) {
    gslogFunctionExit(functionName);
  }

  return mlkemkeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    MLKEMKEY_createPrivateKey
 * Signature: (J[B)J
 */
JNIEXPORT jlong JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_MLKEMKEY_1createPrivateKey
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jbyteArray privateKeyBytes)
{
  static const char * functionName = "NativeInterface.MLKEMKEY_createPrivateKey";

  ICC_CTX *       ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_RSA *       ockRSA = NULL;
  ICC_EVP_PKEY *  ockPKey = NULL;
  unsigned char * keyBytesNative = NULL;
  jboolean        isCopy = 0;
  jlong           mlkemkeyId = 0;
  unsigned char * pBytes = NULL;
  jint            size = 0;

  if( debug ) {
    gslogFunctionEntry(functionName);
  }

  if (privateKeyBytes == NULL) {
    throwOCKException(env, 0, "The RSA Key Private Key bytes are incorrect.");
	if( debug ) {
	  gslogFunctionExit(functionName);
	}
	return mlkemkeyId;
  }
  keyBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, privateKeyBytes, &isCopy));
  if( NULL == keyBytesNative ) {
#ifdef DEBUG_RSA_DETAIL
    if ( debug ) {
       gslogMessage ("DETAIL_RSA  FAILURE keyBytesNative");
    }
#endif
    throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
  } else {
    if ( debug ) {
      gslogMessage ("DETAIL_RSA KeyBytesNative allocated");
    }
//  unsigned char * pBytes = (unsigned char *)keyBytesNative;
    pBytes = (unsigned char *)keyBytesNative;
//  jint size = (*env)->GetArrayLength(env, privateKeyBytes);
    size = (*env)->GetArrayLength(env, privateKeyBytes);
#ifdef DEBUG_RSA_DATA
    if ( debug ) {
      gslogMessagePrefix ("DATA_RSA Private KeyBytes : ");
      gslogMessageHex ((char *) pBytes, 0, (int) size, 0, 0, NULL);
    }
#endif

    ockPKey = ICC_EVP_PKEY_new(ockCtx);
    if( NULL == ockPKey ) {
      ockCheckStatus(ockCtx);
#ifdef DEBUG_RSA_DETAIL
    if ( debug ) {
       gslogMessage ("DETAIL_RSA  FAILURE ICC_EVP_PKEY_new ");
    }
#endif
      throwOCKException(env, 0, "ICC_EVP_PKEY_new failed");
    } else {
      ICC_EVP_PKEY * ret = ICC_d2i_PrivateKey(ockCtx, 6, &ockPKey, &pBytes, (long)size);
#ifdef DEBUG_RSA_DETAIL
    if ( debug ) {
      gslogMessage ("DETAIL_RSA pointer to ICC_EVP_PKEY %x", ret);
    }
#endif
      if( ret == NULL ) {
        ockCheckStatus(ockCtx);
#ifdef DEBUG_RSA_DETAIL
        if ( debug ) {
          gslogMessage ("DETAIL_RSA  FAILURE ICC_d2i_PrivateKey");
        }
#endif
        throwOCKException(env, 0, "ICC_d2i_PrivateKey failed");
      } else {
        ockRSA = ICC_EVP_PKEY_get1_RSA(ockCtx, ockPKey);
        if( ockRSA == NULL ) {
#ifdef DEBUG_RSA_DETAIL
          if ( debug ) {
            gslogMessage ("DETAIL_RSA  FAILURE ICC_EVP_PKEY_get1_RSA");
          }
#endif
          ockCheckStatus(ockCtx);
          throwOCKException(env, 0, "ICC_EVP_PKEY_get1_RSA failed");
        } else {
          mlkemkeyId = (jlong)((intptr_t)ockRSA);
#ifdef DEBUG_RSA_DETAIL
          if ( debug ) {
            gslogMessage ("DETAIL_RSA  mlkemkeyId %lx", mlkemkeyId);
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

  return mlkemkeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    MLKEMKEY_createPublicKey
 * Signature: (J[B)J
 */
JNIEXPORT jlong JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_MLKEMKEY_1createPublicKey
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jbyteArray publicKeyBytes)
{
  static const char * functionName = "NativeInterface.MLKEMKEY_createPublicKey";

  ICC_CTX *       ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_RSA *       ockRSA = NULL;
  ICC_EVP_PKEY *  ockPKey = NULL;
  unsigned char * keyBytesNative = NULL;
  jboolean        isCopy = 0;
  jlong           mlkemkeyId = 0;
  unsigned char * pBytes = NULL;
  jint            size = 0;

  if( debug ) {
    gslogFunctionEntry(functionName);
  }
  if (publicKeyBytes == NULL) {
    throwOCKException(env, 0, "The RSA Key Public bytes are incorrect.");
	if( debug ) {
	  gslogFunctionExit(functionName);
	}
	return mlkemkeyId;
  }
  keyBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, publicKeyBytes, &isCopy));
  if( NULL == keyBytesNative ) {
#ifdef DEBUG_RSA_DETAIL
    if ( debug ) {
      gslogMessage ("DETAIL_RSA  FAILURE keyBytesNative");
    }
#endif
    throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
  } else {

#ifdef DEBUG_RSA_DETAIL
    if ( debug ) {
      gslogMessage ("DETAIL_RSA KeyBytesNative allocated");
    }
#endif
    pBytes = (unsigned char *)keyBytesNative;
    size = (*env)->GetArrayLength(env, publicKeyBytes);
#ifdef DEBUG_RSA_DATA
    if ( debug ) {
      gslogMessagePrefix ("DATA_RSA PublicKeyBytes : ");
      gslogMessageHex ((char *) pBytes, 0, (int) size, 0, 0, NULL);
    }
#endif

    ockPKey = ICC_EVP_PKEY_new(ockCtx);
    if( NULL == ockPKey ) {
      ockCheckStatus(ockCtx);
#ifdef DEBUG_RSA_DETAIL
    if ( debug ) {
      gslogMessage ("DETAIL_RSA  FAILURE ICC_EVP_PKEY_new");
    }
#endif
      throwOCKException(env, 0, "ICC_EVP_PKEY_new failed");
    } else {
      ICC_EVP_PKEY * ret = ICC_d2i_PublicKey(ockCtx, ICC_EVP_PKEY_RSA, &ockPKey, &pBytes, (int)size);
#ifdef DEBUG_RSA_DETAIL
          if ( debug ) {
            gslogMessage ("DETAIL_RSA ICC_EVP_PKEY  %x", ret);
          }
#endif
      if( ret == NULL ) {
#ifdef DEBUG_RSA_DETAIL
        if ( debug ) {
          gslogMessage ("DETAIL_RSA  FAILURE ICC_d2i_PublicKey");
        }
#endif
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_d2i_PublicKey failed");
      } else {
        ockRSA = ICC_EVP_PKEY_get1_RSA(ockCtx, ockPKey);
        if( ockRSA == NULL ) {
#ifdef DEBUG_RSA_DETAIL
          if ( debug ) {
            gslogMessage ("DETAIL_RSA  FAILURE ICC_EVP_PKEY_get1_RSA");
          }
#endif
          ockCheckStatus(ockCtx);
          throwOCKException(env, 0, "ICC_EVP_PKEY_get1_RSA failed");
        } else {
          mlkemkeyId = (jlong)((intptr_t)ockRSA);
#ifdef DEBUG_RSA_DETAIL
          if ( debug ) {
            gslogMessage ("DETAIL_RSA mlkemkeyId  %lx", (long) mlkemkeyId);
          }
#endif
        }
      }
    }
  }

  if( keyBytesNative != NULL ) {
    (*env)->ReleasePrimitiveArrayCritical(env, publicKeyBytes, keyBytesNative, 0);
  }

  if( ockPKey != NULL ) {
    ICC_EVP_PKEY_free(ockCtx, ockPKey);
    ockPKey = NULL;
  }

  if( debug ) {
    gslogFunctionExit(functionName);
  }

  return mlkemkeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    MLKEMKEY_getPrivateKeyBytes
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_MLKEMKEY_1getPrivateKeyBytes
  (JNIEnv * env, jclass thisObj, jlong ockContextId, jlong mlkemkeyId)
{
  static const char * functionName = "NativeInterface.MLKEMKEY_getPrivateKeyBytes";

  ICC_CTX *       ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_RSA *       ockRSA = (ICC_RSA *)((intptr_t) mlkemkeyId);
  jbyteArray      keyBytes = NULL;
  unsigned char * keyBytesNative = NULL;
  jboolean        isCopy = 0;
  int             size;
  jbyteArray      retKeyBytes = NULL;

  if( debug ) {
    gslogFunctionEntry(functionName);
  }

  if (ockRSA == NULL) {
    throwOCKException(env, 0, "The RSA Key identifier is incorrect.");
	if( debug ) {
	  gslogFunctionExit(functionName);
	}
	return retKeyBytes;
  }

#ifdef DEBUG_RSA_DETAIL
   if ( debug ) {
     gslogMessage ("DETAIL_RSA mlkemkeyId  %lx", (long) mlkemkeyId);
   }
#endif
  size = ICC_i2d_RSAPrivateKey(ockCtx, ockRSA, NULL);
  if( size <= 0 ) {
#ifdef DEBUG_RSA_DETAIL
    if ( debug ) {
      gslogMessage ("DETAIL_RSA  FAILURE ICC_i2d_RSAPrivateKey");
    }
#endif
    ockCheckStatus(ockCtx);
    throwOCKException(env, 0, "ICC_i2d_RSAPrivateKey failed");
  } else {
    keyBytes = (*env)->NewByteArray(env, size);
    if( keyBytes == NULL ) {
#ifdef DEBUG_RSA_DETAIL
      if ( debug ) {
        gslogMessage ("DETAIL_RSA  FAILURE keyBytes");
      }
#endif
      throwOCKException(env, 0, "NewByteArray failed");
    } else {
      keyBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, keyBytes, &isCopy));
      if( keyBytesNative == NULL ) {
#ifdef DEBUG_RSA_DETAIL
        if ( debug ) {
          gslogMessage ("DETAIL_RSA  FAILURE keyBytesNative ");
        }
#endif
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical");
      } else {
        unsigned char * pBytes = (unsigned char *)keyBytesNative;

        size = ICC_i2d_RSAPrivateKey(ockCtx, ockRSA, &pBytes);
        if( size <= 0 ) {
          ockCheckStatus(ockCtx);
#ifdef DEBUG_RSA_DETAIL
        if ( debug ) {
          gslogMessage ("DETAIL_RSA  FAILURE ICC_i2d_RSAPrivateKey");
        }
#endif
          throwOCKException(env, 0, "ICC_i2d_RSAPrivateKey failed");
        } else {
          retKeyBytes = keyBytes;
#ifdef DEBUG_RSA_DATA
          if ( debug ) {
            gslogMessagePrefix ("DATA_RSA private KeyBytes : ");
            gslogMessageHex ((char *) pBytes, 0, (int) size, 0, 0, NULL);
          }
#endif
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

  if( debug ) {
    gslogFunctionExit(functionName);
  }

  return retKeyBytes;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    MLKEMKEY_getPublicKeyBytes
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_MLKEMKEY_1getPublicKeyBytes
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jlong mlkemkeyId )
{
  static const char * functionName = "NativeInterface.MLKEMKEY_getPublicKeyBytes";

  ICC_CTX *       ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_RSA *       ockRSA = (ICC_RSA *)((intptr_t) mlkemkeyId);
  jbyteArray      keyBytes = NULL;
  unsigned char * keyBytesNative = NULL;
  jboolean        isCopy = 0;
  int             size;
  jbyteArray      retKeyBytes = NULL;

  if( debug ) {
    gslogFunctionEntry(functionName);
  }

  if (ockRSA == NULL) {
    throwOCKException(env, 0, "The RSA Key identifier is incorrect.");
  	if( debug ) {
  	  gslogFunctionExit(functionName);
  	}
  	return retKeyBytes;
  }
  size = ICC_i2d_RSAPublicKey(ockCtx, ockRSA, NULL);
#ifdef DEBUG_RSA_DETAIL
          if ( debug ) {
            gslogMessage ("DETAIL_RSA mlkemkeyId %lx size %d ", (long) mlkemkeyId, (int) size);
          }
#endif
  if( size <= 0 ) {
#ifdef DEBUG_RSA_DETAIL
    if ( debug ) {
      gslogMessage ("DETAIL_RSA  FAILURE ICC_i2d_RSAPublicKey");
    }
#endif
    ockCheckStatus(ockCtx);
    throwOCKException(env, 0, "ICC_i2d_RSAPublicKey failed");
  } else {
    keyBytes = (*env)->NewByteArray(env, size);
    if( keyBytes == NULL ) {
#ifdef DEBUG_RSA_DETAIL
    if ( debug ) {
      gslogMessage ("DETAIL_RSA  FAILURE keyBytes ");
    }
#endif
      throwOCKException(env, 0, "NewByteArray failed");
    } else {
      keyBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, keyBytes, &isCopy));
      if( keyBytesNative == NULL ) {
#ifdef DEBUG_RSA_DETAIL
        if ( debug ) {
          gslogMessage ("DETAIL_RSA  FAILURE keyBytesNative ");
        }
#endif
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical");
      } else {
        unsigned char * pBytes = (unsigned char *)keyBytesNative;

        size = ICC_i2d_RSAPublicKey(ockCtx, ockRSA, &pBytes);
        if( size <= 0 ) {
          ockCheckStatus(ockCtx);
#ifdef DEBUG_RSA_DETAIL
          if ( debug ) {
            gslogMessage ("DETAIL_RSA  FAILURE ICC_i2d_RSAPublicKey");
          }
#endif
          throwOCKException(env, 0, "ICC_i2d_RSAPublicKey failed");
        } else {
          retKeyBytes = keyBytes;
#ifdef DEBUG_RSA_DATA
    if ( debug ) {
      gslogMessagePrefix ("DATA_RSA KeyBytes : ");
      gslogMessageHex ((char *) pBytes, 0, (int) size, 0, 0, NULL);
    }
#endif
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

  if( debug ) {
    gslogFunctionExit(functionName);
  }

  return keyBytes;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    MLKEMKEY_createPKey
 * Signature: (JJ)J
 */
JNIEXPORT jlong JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_MLKEMKEY_1createPKey
  (JNIEnv * env, jclass thisObj, jlong ockContextId, jlong mlkemkeyId)
{
  static const char * functionName = "NativeInterface.MLKEMKEY_createPKey";

  ICC_CTX *      ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_RSA *      ockRSA = (ICC_RSA *)((intptr_t) mlkemkeyId);
  ICC_EVP_PKEY * ockPKey = NULL;
  jlong          pkeyId = 0;

  if( debug ) {
    gslogFunctionEntry(functionName);
  }

  if (ockRSA == NULL) {
    throwOCKException(env, 0, "The RSA Key identifier is incorrect.");
  	if( debug ) {
  	  gslogFunctionExit(functionName);
  	}
  	return pkeyId;
  }
#ifdef DEBUG_RSA_DETAIL
  if ( debug ) {
    gslogMessage ("DETAIL_RSA mlkemkeyId %lx ", (long) mlkemkeyId);
  }
#endif

  ockPKey = ICC_EVP_PKEY_new(ockCtx);
  if( ockPKey == NULL ) {
#ifdef DEBUG_RSA_DETAIL
    if ( debug ) {
      gslogMessage ("DETAIL_RSA  FAILURE ICC_EVP_PKEY_new");
    }
#endif
    ockCheckStatus(ockCtx);
    throwOCKException(env, 0, "ICC_EVP_PKEY_new failed");
  } else {
    int rc = ICC_EVP_PKEY_set1_RSA(ockCtx, ockPKey, ockRSA);
#ifdef DEBUG_RSA_DETAIL
    if ( debug ) {
      gslogMessage ("DETAIL_RSA rc from ICC_EVP_PKEY_set1_RSA %d ", rc);
    }
#endif
    if( rc != ICC_OSSL_SUCCESS ) {
      ockCheckStatus(ockCtx);
#ifdef DEBUG_RSA_DETAIL
    if ( debug ) {
      gslogMessage ("DETAIL_RSA  FAILURE ICC_EVP_PKEY_set1_RSA %d", rc);
    }
#endif
      throwOCKException(env, 0, "ICC_EVP_PKEY_set1_RSA failed");
    } else {
      pkeyId = (jlong)((intptr_t)ockPKey);
#ifdef DEBUG_RSA_DETAIL
    if ( debug ) {
      gslogMessage ("DETAIL_RSA pkeyId %lx=", pkeyId);
    }
#endif
    }
  }

  if( (ockPKey != NULL) && (pkeyId == 0) ) {
    ICC_EVP_PKEY_free(ockCtx, ockPKey);
    ockPKey = NULL;
  }

  if( debug ) {
    gslogFunctionExit(functionName);
  }

  return pkeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    MLKEMKEY_size
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_MLKEMKEY_1size
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jlong mlkemkeyId) {

  static const char * functionName = "NativeInterface.MLKEMKEY_size";

  ICC_CTX * ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_RSA * ockRSA = (ICC_RSA *)((intptr_t) mlkemkeyId);
  int       size = 0;

  if( debug ) {
    gslogFunctionEntry(functionName);
  }

  if (ockRSA == NULL) {
    throwOCKException(env, 0, "The RSA Key identifier is incorrect.");
  	if( debug ) {
      gslogFunctionExit(functionName);
  	}
  	return size;
  }
#ifdef DEBUG_RSA_DETAIL
  if ( debug ) {
    gslogMessage("DETAIL_RSA mlkemkeyId=%lx", (long) mlkemkeyId);
  }
#endif

  size = ICC_RSA_size(ockCtx, ockRSA);
#ifdef DEBUG_RSA_DETAIL
  if ( debug ) {
    gslogMessage("DETAIL_RSA size=%d", size);
  }
#endif

  if( debug ) {
    gslogFunctionExit(functionName);
  }

  return size;

}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    MLKEMKEY_delete
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_MLKEMKEY_1delete
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jlong mlkemkeyId)
{
  static const char * functionName = "NativeInterface.MLKEMKEY_delete";

  ICC_CTX * ockCtx = (ICC_CTX *)((intptr_t) ockContextId);
  ICC_RSA * ockRSA = (ICC_RSA *)((intptr_t) mlkemkeyId);

  if( debug ) {
    gslogFunctionEntry(functionName);
  }
#ifdef DEBUG_RSA_DETAIL
  if ( debug ) {
    gslogMessage("DETAIL_RSA mlkemkeyId=%lx", (long) mlkemkeyId);
  }
#endif
  if (ockRSA != NULL) {
	  ICC_RSA_free(ockCtx, ockRSA);
	  ockRSA = NULL;
  }

  if( debug ) {
    gslogFunctionExit(functionName);
  }
}
