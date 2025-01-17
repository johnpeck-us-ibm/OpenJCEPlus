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
#include <string.h>
#include <assert.h>
#include <jcc_a.h>
#include <icc.h>

#include "com_ibm_crypto_plus_provider_ock_NativeInterface.h"
#include "Utils.h"
#include "Digest.h"
#include <stdint.h>

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    SIGNATURE_sign
 * Signature: (JJJ)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_SIGNATURE_1sign
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockPKeyId, jbyteArray data) {

  static const char * functionName = "NativeInterface.SIGNATURE_sign";

  ICC_CTX *          ockCtx = (ICC_CTX *) ((intptr_t) ockContextId);
  ICC_EVP_PKEY *     ockPKey = (ICC_EVP_PKEY *) ((intptr_t) ockPKeyId);
  ICC_EVP_PKEY_CTX * skc = NULL;
  unsigned char *    sigBytesLocal = NULL;
  jbyteArray         sigBytes = NULL;
  unsigned char *    sigBytesNative = NULL;
  unsigned char *    dataNative = NULL;
  jboolean           isCopy = 0;
  int                sigLen = 0;
  int                datalen = 0;
  unsigned int       outLen = 0;
  int                rc = ICC_OSSL_SUCCESS;
  jbyteArray         retSigBytes = NULL;

  
  if ((ockPKey == NULL) || (data == NULL)) {
    throwOCKException(env, 0, "Signature sign failed. The specified Signature input parameters are incorrect.");
    return retSigBytes;
  }

  skc = ICC_EVP_PKEY_CTX_new(ockCtx, ockPKey, NULL);
  if (skc == NULL) {
    throwOCKException(env, 0, "Signature sign failed. ICC_EVP_PKEY_CTX_new failed.");
    return retSigBytes;
  }

  rc = ICC_EVP_PKEY_sign_init(ockCtx, skc);
  if( ICC_OSSL_SUCCESS != rc ) {
    ockCheckStatus(ockCtx);
    throwOCKException(env, 0, "ICC_EVP_PKEY_sign_init failed");
    return retSigBytes;
  }
  /* Get the lenght of the signature to allocate 
  */
 datalen = (*env)->GetArrayLength(env, data);
 
 if (datalen == 0) {
    throwOCKException(env, 0, "Signature sign failed. Lenght of data to sign is 0.");
    return retSigBytes;
  }

  rc = ICC_EVP_PKEY_sign(ockCtx, skc, NULL, &sigLen, data, datalen);
  if( ICC_OSSL_SUCCESS != rc ) {
    ockCheckStatus(ockCtx);
    throwOCKException(env, 0, "ICC_EVP_PKEY_sign_init failed");
    return retSigBytes;
  }

  if( sigLen <= 0 ) {
    ockCheckStatus(ockCtx);
    throwOCKException(env, 0, "Getting signature size failed");
  } else {
    sigBytesLocal = (unsigned char *)malloc(sigLen);
    if( sigBytesLocal == NULL ) {
      throwOCKException(env, 0, "malloc failed");
    } else {
      dataNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, data,  &isCopy));
      if( NULL == dataNative) {
        throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
      } else {
        rc = ICC_EVP_PKEY_sign(ockCtx, skc, sigBytesLocal, &sigLen, dataNative, datalen);
        if( ICC_OSSL_SUCCESS != rc ) {
          ockCheckStatus(ockCtx);
          throwOCKException(env, 0, "ICC_EVP_SignFinal failed");
        } else {
          sigBytes = (*env)->NewByteArray(env, outLen);
          if( sigBytes == NULL ) {
          throwOCKException(env, 0, "NewByteArray failed");
          } else {
            sigBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, sigBytes, &isCopy));
            if( sigBytesNative == NULL ) {
              throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical");
            } else {
              memcpy(sigBytesNative, sigBytesLocal, outLen);
              retSigBytes = sigBytes;
            }
          }
        }  
      }
    }
  }

  if( sigBytesLocal != NULL ) {
    free( sigBytesLocal );
    sigBytesLocal = NULL;
  }
  if( dataNative != NULL ) {
    (*env)->ReleasePrimitiveArrayCritical(env, data,  dataNative, 0);
  }
  if( sigBytesNative != NULL ) {
    (*env)->ReleasePrimitiveArrayCritical(env, sigBytes,  sigBytesNative, 0);
  }

  if( (dataNative != NULL) && (retSigBytes == NULL) ) {
    (*env)->DeleteLocalRef(env, dataNative);
  }  
  if( (sigBytes != NULL) && (retSigBytes == NULL) ) {
    (*env)->DeleteLocalRef(env, sigBytes);
  }

  return retSigBytes;
}

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    SIGNATURE_verify
 * Signature: (JJJ)Z
 */
JNIEXPORT jboolean JNICALL Java_com_ibm_crypto_plus_provider_ock_NativeInterface_SIGNATURE_1verify
  (JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockPKeyId, jbyteArray sigBytes, jbyteArray data) {

  static const char * functionName = "NativeInterface.SIGNATURE_verify";

  ICC_CTX *          ockCtx = (ICC_CTX *) ((intptr_t) ockContextId);
  ICC_EVP_PKEY *     ockPKey = (ICC_EVP_PKEY *) ((intptr_t) ockPKeyId);
  ICC_EVP_PKEY_CTX * evp_pk = NULL;
  unsigned char *    sigBytesNative = NULL;
  unsigned char *    dataNative = NULL;
  jboolean           isCopy = 0;
  int                rc = ICC_OSSL_SUCCESS;
  jint               sigsize = 0;
  jint               datalen = 0;
  jboolean           verified = 0;
  unsigned long      errCode;

  if ((ockPKey == NULL) || (sigBytes == NULL)) {
    throwOCKException(env, 0, "Verify failed. The specified input parameters are incorrect.");
    return verified;
  }

  sigBytesNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, sigBytes,  &isCopy));
  if (sigBytesNative == NULL) {
    throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
  } else {
    sigsize = (*env)->GetArrayLength(env, sigBytes);
    dataNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, data,  &isCopy));

    if(dataNative == NULL) {
      throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
    } else {
      datalen = (*env)->GetArrayLength(env, data);

      /* EVP context */
      evp_pk = ICC_EVP_PKEY_CTX_new(ockCtx, ockPKey, NULL);

      if (!evp_pk) {
        throwOCKException(env, 0, "ICC_EVP_PKEY_CTX_new failed");
      } else {
        rc = ICC_EVP_PKEY_verify_init(ockCtx, evp_pk);

        if (rc != ICC_OSSL_SUCCESS) {
          throwOCKException(env, 0, "ICC_EVP_PKEY_verify_init failed");
        } else {
          rc = ICC_EVP_PKEY_verify(ockCtx, evp_pk, sigBytesNative, sigsize, dataNative, datalen);
          if( ICC_OSSL_SUCCESS == rc ) {
            verified = 1;
          } else {
            errCode = ICC_ERR_peek_last_error(ockCtx);

            if (errCode == 0x0D08303A) {
              throwOCKException(env, 0, "nested asn1 error");
            } else {
              ockCheckStatus(ockCtx);
              throwOCKException(env, 0, "ICC_EVP_VerifyFinal failed");         
            }         
          }
        }
      }
    }
  }
  if ( evp_pk != NULL ) {
    ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
  }

  if( sigBytesNative != NULL ) {
    (*env)->ReleasePrimitiveArrayCritical(env, sigBytes,  sigBytesNative, 0);
  }
  if( dataNative != NULL ) {
    (*env)->ReleasePrimitiveArrayCritical(env, data,  dataNative, 0);
  }

  return verified;
}
