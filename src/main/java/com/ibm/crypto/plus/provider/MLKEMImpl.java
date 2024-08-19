/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import javax.crypto.KEMSpi;

public static class MLKEMImpl implements KEMSpi {
    
    @Override
    public KEMSpi.EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey,
                 AlgorithmParameterSpec spec, SecureRandom secureRandom)
                 throws InvalidAlgorithmParameterException, InvalidKeyException {
             if (!checkPublicKey(publicKey)) {
                 throw new InvalidKeyException("unsupported key");
             }
             if (!checkParameters(spec)) {
                 throw new InvalidAlgorithmParameterException("unsupported params");
             }
             return new MyEncapsulator(publicKey, spec, null);
    }
    
    class MyEncapsulator implements KEMSpi.EncapsulatorSpi {

            PublicKey publicKey;
            AlgorithmParameterSpec spec;

             MyEncapsulator(PublicKey publicKey, AlgorithmParameterSpec spec,
                     SecureRandom secureRandom){
                 this.spec = spec != null ? spec : getDefaultParameters();
                 this.publicKey = publicKey;
            }
    
            @Override
            public KEM.Encapsulated engineEncapsulate(int from, int to, String algorithm) {
                 byte[] encapsulation;
                 byte[] secret;
                 // call out to OCKC for thing
                 getSharedSecretandCiphertext(publicKey)
                 this.size = to - from + 1;
                 return new KEM.Encapsulated(
                         new SecretKeySpec(secret, from, to - from, algorithm),
                         encapsulation, null);
             }
             
             @Override
             public int engineEncapsulationSize() {
                  return ((MLKEMParameters)spec).cipherTextSize;
              }
              @Override
              public int engineSecretSize() {
                return this.size;
               }
    }

    @Override
    public KEMSpi.DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey,
                 AlgorithmParameterSpec spec)
                 throws InvalidAlgorithmParameterException, InvalidKeyException {
             if (!checkPrivateKey(privateKey)) {
                 throw new InvalidKeyException("unsupported key");
             }
             if (!checkParameters(spec)) {
                 throw new InvalidAlgorithmParameterException("unsupported params");
             }
             return new MLKEMDecapsulator(publicKey, spec, null);
    }

    class MLKEMDecapsulator implements KEMSpi.DecapsulatorSpi {
        MyDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec){
            this.spec = spec != null ? spec : getDefaultParameters();
            this.publicKey = publicKey;
       }

       @Override
       public SecretKey engineDecapsulate(byte[] cipherText, int from, int to, String algorithm) {
           
            byte[] secret;
            // call out to OCKC for thing
            getSharedSecretandCiphertext(publicKey)
            
            return new SecretKey()
        }

        @Override
        public int engineDecapsulateSize() {

             return this.spec.getCipherTextLen();
         }
         
        @Override
        public int engineSecretSize() {

             return this.spec.getSecretKeySize();
         }
    }
}